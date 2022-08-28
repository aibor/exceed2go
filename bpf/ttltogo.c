#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define __CTX_OFF_MAX			0xff

#define unlikely(x)     __builtin_expect(!!(x), 0)
#define BPF_FUNC_REMAP(NAME, ...)					\
	(* NAME)(__VA_ARGS__)

# define BPF_STUB(NAME, ...)						\
	(* NAME##__stub)(__VA_ARGS__) = (void *)((__u32)-1)

#define DEFAULT_ACTION		XDP_PASS
#define ETH_HLEN			14
#define ETH_ALEN			6
#define ETH_TLEN			2
#define ETH_SRC_OFF			(offsetof(struct ethhdr), h_source)
#define ETH_DST_OFF			(offsetof(struct ethhdr), h_dest)
#define ETH_PROTO_OFF		(offsetof(struct ethhdr), h_proto)
#define ETH_P_IPV6			0x86DD
#define IPV6_MTU_MIN		1280
#define IPV6_SRC_OFF		(ETH_HLEN + offsetof(struct ipv6hdr, saddr))
#define IPV6_DST_OFF		(ETH_HLEN + offsetof(struct ipv6hdr, daddr))
#define IPV6_PROTO_OFF		(ETH_HLEN + offsetof(struct ipv6hdr, nexthdr))
#define IPPROTO_ICMPV6		58
#define ICMP6_TIME_EXCEEDED	3
#define ICMP6_CSUM_OFFSET	(ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))
#define ADD_HDR_LEN			(sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define bpf_memcpy __builtin_memcpy

#define IN6_ARE_ADDR_EQUAL(a,b) \
	((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0])	      \
	 && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1])      \
	 && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2])      \
	 && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct in6_addr);
		__uint(max_entries, 32);
} ttl_addrs SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum) {
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

static __always_inline __sum16 csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

static int BPF_FUNC_REMAP(csum_diff_external, const void *from, __u32 size_from,
			  const void *to, __u32 size_to, __u32 seed) =
	(void *)BPF_FUNC_csum_diff;

#define CSUM_MANGLED_0		((__sum16)0xffff)

static __always_inline void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static __always_inline void
__csum_replace_by_4(__sum16 *sum, __wsum from, __wsum to)
{
	__csum_replace_by_diff(sum, csum_add(~from, to));
}

static __always_inline int
l4_csum_replace(const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -1;
	if (unlikely(size != 0 && size != 2))
		return -1;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-1)
		     : "r1", "r2");
	if (!ret) {
		if (is_mmzero && !*sum)
			return 0;
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
		if (is_mmzero && !*sum)
			*sum = CSUM_MANGLED_0;
	}
	return ret;
}

static __always_inline __wsum csum_diff(const void *from, __u32 size_from,
										const void *to,   __u32 size_to,
										__u32 seed) {
	if (__builtin_constant_p(size_from) &&
	    __builtin_constant_p(size_to)) {
		/* Optimizations for frequent hot-path cases that are tiny to just
		 * inline into the code instead of calling more expensive helper.
		 */
		if (size_from == 4 && size_to == 4 &&
		    __builtin_constant_p(seed) && seed == 0)
			return csum_add(~(*(__u32 *)from), *(__u32 *)to);
		if (size_from == 4 && size_to == 4)
			return csum_add(seed,
					csum_add(~(*(__u32 *)from),
						 *(__u32 *)to));
	}

	return csum_diff_external(from, size_from, to, size_to, seed);
}

static __always_inline __be32 ipv6_pseudohdr_checksum(struct ipv6hdr *hdr,
												      __u8 next_hdr,
												      __u16 payload_len,
													  __be32 sum) {
	__be32 len = bpf_htonl((__u32)payload_len);
	__be32 nexthdr = bpf_htonl((__u32)next_hdr);

	sum = csum_diff(NULL, 0, &hdr->saddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &hdr->daddr, sizeof(struct in6_addr), sum);
	sum = csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	return sum;
}

static __always_inline __be32 compute_icmp6_csum(char data[80],
												 __u16 payload_len,
												 struct ipv6hdr *ipv6hdr) {
	__be32 sum;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, data, payload_len, 0);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	return sum;
}

SEC("xdp")
int xdp_ttltogo(struct xdp_md *ctx) {
	void *data		= (void *)(unsigned long)ctx->data;
	void *data_end	= (void *)(unsigned long)ctx->data_end;
	void *nexthdr	= data;
	int len			= data_end - data;

	bpf_printk("entry");

	return DEFAULT_ACTION;

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth = nexthdr;
	nexthdr += sizeof(*eth);

	bpf_printk("eth");

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return DEFAULT_ACTION;

	struct ipv6hdr *ipv6 = nexthdr;
	nexthdr += sizeof(*ipv6);

	__u32 target_key = 0;
	struct in6_addr *target = bpf_map_lookup_elem(&ttl_addrs, &target_key);

	bpf_printk("ipv6");

	if (!target)
		return DEFAULT_ACTION;

	bpf_printk("ipv6 target");

	if (IN6_ARE_ADDR_EQUAL(&ipv6->saddr, target))
		return DEFAULT_ACTION;

	__u32 hop_key = ipv6->hop_limit;
	struct in6_addr *ttl_addr = bpf_map_lookup_elem(&ttl_addrs, &hop_key);

	if (!ttl_addr)
		return DEFAULT_ACTION;

	if (bpf_xdp_adjust_head(ctx, 0 - (int)ADD_HDR_LEN) != 0)
		return XDP_DROP;

	int len_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - len;
	if (len < 0)
		bpf_xdp_adjust_tail(ctx, len_adjust);

	data		= (void *)(long)ctx->data;
	data_end	= (void *)(long)ctx->data_end;
	nexthdr		= data;
	len			= data_end - data;

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + (int)ADD_HDR_LEN > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth_n = data;
	nexthdr += sizeof(*eth_n);
	struct ethhdr *eth_o = data + (int)ADD_HDR_LEN;

	__u8 h_tmp_src[ETH_ALEN];
    __u8 h_tmp_dst[ETH_ALEN];

	bpf_memcpy(h_tmp_src, eth_o->h_source, ETH_ALEN);
	bpf_memcpy(h_tmp_dst, eth_o->h_dest, ETH_ALEN);

	bpf_memcpy(eth_n->h_source, h_tmp_dst, ETH_ALEN);
	bpf_memcpy(eth_n->h_dest, h_tmp_src, ETH_ALEN);
	eth_n->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ipv6_n = nexthdr;
	nexthdr += sizeof(*ipv6_n);
	struct ipv6hdr *ipv6_o = data + (int)ADD_HDR_LEN + sizeof(*eth_o);

	__u16 payload_len = len - sizeof(struct ipv6hdr);
	if (payload_len > IPV6_MTU_MIN - sizeof(struct ipv6hdr))
		payload_len = IPV6_MTU_MIN - sizeof(struct ipv6hdr);

	if ((void *)(long)ipv6_o + payload_len > data_end)
		return XDP_DROP;

	bpf_memcpy(ipv6_n->flow_lbl, ipv6_o->flow_lbl, sizeof(ipv6_n->flow_lbl));

	ipv6_n->priority	= ipv6_o->priority;
	ipv6_n->version		= ipv6_o->version;
	ipv6_n->payload_len = bpf_htons(payload_len);
	ipv6_n->nexthdr		= IPPROTO_ICMPV6;
	ipv6_n->hop_limit	= 64;
	ipv6_n->saddr		= *ttl_addr;
	ipv6_n->daddr		= ipv6_o->saddr;

	struct icmp6hdr *icmp6 = nexthdr;

	icmp6->icmp6_type					= ICMP6_TIME_EXCEEDED;
	icmp6->icmp6_code					= 0;
	icmp6->icmp6_cksum					= 0;
	icmp6->icmp6_dataun.un_data32[0]	= 0;

	//__be32 sum = compute_icmp6_csum((void *)(long)icmp6, payload_len, ipv6_o);
	__be32 sum = 0x1234;
	if (l4_csum_replace(ctx, ICMP6_CSUM_OFFSET, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return XDP_DROP;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
