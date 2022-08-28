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
#define ADD_HDR_LEN			(sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define bpf_memcpy __builtin_memcpy

# define IN6_ARE_ADDR_EQUAL(a,b) \
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

//static __always_inline __u16 csum_fold(__u32 csum) {
//	csum = (csum & 0xffff) + (csum >> 16);
//	csum = (csum & 0xffff) + (csum >> 16);
//	return (__u16)~csum;
//}
//
//static __always_inline __u16 csum_ipv6_magic(const struct in6_addr *saddr,
//											const struct in6_addr *daddr,
//											__u32 len, __u8 proto, __u32 csum) {
//	__u64 sum = csum;
//	int i;
//
//#pragma unroll
//	for (i = 0; i < 4; i++)
//		sum += (__u32)saddr->in6_u.u6_addr32[i];
//
//#pragma unroll
//	for (i = 0; i < 4; i++)
//		sum += (__u32)daddr->in6_u.u6_addr32[i];
//
//	/* Don't combine additions to avoid 32-bit overflow. */
//	sum += bpf_htonl(len);
//	sum += bpf_htonl(proto);
//
//	sum = (sum & 0xffffffff) + (sum >> 32);
//	sum = (sum & 0xffffffff) + (sum >> 32);
//
//	return csum_fold((__u32)sum);
//}

SEC("xdp")
int xdp_ttltogo(struct xdp_md *ctx) {
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;
	void *nexthdr = data;

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth = nexthdr;
	nexthdr += sizeof(*eth);

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return DEFAULT_ACTION;

	struct ipv6hdr *ipv6 = nexthdr;
	nexthdr += sizeof(*ipv6);


	__u32 target_key = 0;
	struct in6_addr *target = bpf_map_lookup_elem(&ttl_addrs, &target_key);

	if (!target)
		return DEFAULT_ACTION;

	if (IN6_ARE_ADDR_EQUAL(&ipv6->saddr, target))
		return DEFAULT_ACTION;

	__u32 hop_key = ipv6->hop_limit;
	struct in6_addr *ttl_addr = bpf_map_lookup_elem(&ttl_addrs, &hop_key);

	if (!ttl_addr)
		return DEFAULT_ACTION;

	if (bpf_xdp_adjust_head(ctx, 0 - (int)ADD_HDR_LEN) != 0)
		return XDP_DROP;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nexthdr = data;
	int len = data_end - data;

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

	ipv6_n->priority	= ipv6_o->priority;
	ipv6_n->version		= ipv6_o->version;
	bpf_memcpy(ipv6_n->flow_lbl, ipv6_o->flow_lbl, sizeof(ipv6_n->flow_lbl));
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

	int len_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - len;
	if (len < 0)
		bpf_xdp_adjust_tail(ctx, len_adjust);

	//icmp6->icmp6_cksum = bpf_csum_diff(0, 0, (__be32 *)icmp6, payload_len, 0);

	return XDP_TX;
}
