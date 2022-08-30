#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

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

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
		__uint(max_entries, 8);
} ttl_counters SEC(".maps");

enum ttl_counter_key {
	TTL_COUNTER_KEY_ENTRY,
	TTL_COUNTER_KEY_IPV6,
	TTL_COUNTER_KEY_TARGET,
	TTL_COUNTER_KEY_FOUND
};

//static __always_inline __u16 csum_fold(__u32 csum) {
//	csum = (csum & 0xffff) + (csum >> 16);
//	csum = (csum & 0xffff) + (csum >> 16);
//	return (__u16)~csum;
//}

static __always_inline __sum16 csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
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

	return bpf_csum_diff((__u32 *)from, size_from, (__u32 *)to, size_to, seed);
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

static __always_inline __be32 compute_icmp6_csum(struct icmp6hdr *icmp6hdr,
												 __u16 payload_len,
												 struct ipv6hdr *ipv6hdr) {
	__be32 sum;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, icmp6hdr, payload_len, 0);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	return sum;
}

static __always_inline void counter_increment(__u32 key) {
	__u32 *value = bpf_map_lookup_elem(&ttl_counters, &key);
	if (value) {
		__sync_fetch_and_add(value, 1);
	}
}

SEC("xdp")
int xdp_ttltogo(struct xdp_md *ctx) {
	void *data		= (void *)(unsigned long)ctx->data;
	void *data_end	= (void *)(unsigned long)ctx->data_end;
	void *nexthdr	= data;
	int len			= ctx->data_end - ctx->data;

	bpf_printk("entry");
	counter_increment(TTL_COUNTER_KEY_ENTRY);

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth = nexthdr;
	nexthdr += sizeof(*eth);

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_IPV6);

	struct ipv6hdr *ipv6 = nexthdr;
	nexthdr += sizeof(*ipv6);

	__u32 target_key = 0;
	struct in6_addr *target = bpf_map_lookup_elem(&ttl_addrs, &target_key);

	if (!target)
		return DEFAULT_ACTION;

	if (IN6_ARE_ADDR_EQUAL(&ipv6->saddr, target))
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_TARGET);
	bpf_printk("target");

	__u32 hop_key = ipv6->hop_limit;
	struct in6_addr *ttl_addr = bpf_map_lookup_elem(&ttl_addrs, &hop_key);

	if (!ttl_addr)
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_FOUND);

	if (bpf_xdp_adjust_head(ctx, 0 - (int)ADD_HDR_LEN) != 0)
		return XDP_DROP;

	int len_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - len;
	if (len_adjust < 0)
		bpf_xdp_adjust_tail(ctx, len_adjust);

	data		= (void *)(long)ctx->data;
	data_end	= (void *)(long)ctx->data_end;
	__u64 off		= 0;

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + (int)ADD_HDR_LEN > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth_n = data;
	off += sizeof(struct ethhdr);
	struct ethhdr *eth_o = data + (int)ADD_HDR_LEN;

	bpf_memcpy(eth_n->h_source, eth_o->h_dest, ETH_ALEN);
	bpf_memcpy(eth_n->h_dest, eth_o->h_source, ETH_ALEN);
	eth_n->h_proto = eth_o->h_proto;

	struct ipv6hdr *ipv6_n = data + off;
	off += sizeof(struct ipv6hdr);
	struct ipv6hdr *ipv6_o = data + (int)ADD_HDR_LEN + sizeof(*eth_o);

	__u16 payload_len = data_end - sizeof(struct ethhdr) - sizeof(struct ipv6hdr) - data;

	bpf_memcpy(ipv6_n->flow_lbl, ipv6_o->flow_lbl, sizeof(ipv6_n->flow_lbl));

	ipv6_n->priority	= ipv6_o->priority;
	ipv6_n->version		= ipv6_o->version;
	ipv6_n->payload_len = bpf_htons(payload_len);
	ipv6_n->nexthdr		= IPPROTO_ICMPV6;
	ipv6_n->hop_limit	= 64;
	ipv6_n->saddr		= *ttl_addr;
	ipv6_n->daddr		= ipv6_o->saddr;

	struct icmp6hdr *icmp6 = data + off;

	icmp6->icmp6_type					= ICMP6_TIME_EXCEEDED;
	icmp6->icmp6_code					= 0;
	icmp6->icmp6_cksum					= 0;
	icmp6->icmp6_dataun.un_data32[0]	= 0;

	__be32 sum = compute_icmp6_csum(icmp6, sizeof(struct icmp6hdr), ipv6_o);
	icmp6->icmp6_cksum = sum;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
