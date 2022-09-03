#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define DEFAULT_ACTION		XDP_PASS
#define ETH_ALEN			6
#define ETH_TLEN			2
#define ETH_P_IPV6			0x86DD
#define IPV6_MTU_MIN		1280
#define IPPROTO_ICMPV6		58
#define ICMP6_TIME_EXCEEDED	3
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

static __always_inline __u32 icmp6_csum(struct icmp6hdr *icmp6,
										struct ipv6hdr *ipv6,
										void *data_end) {
	__be32 len = ((__u32)ipv6->payload_len) << 16;
	__be32 nexthdr = ((__u32)ipv6->nexthdr) << 24;
	__be32 sum = 0;

	sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->saddr, sizeof(struct in6_addr), sum);
	sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->daddr, sizeof(struct in6_addr), sum);
	sum = bpf_csum_diff(NULL, 0, &len, sizeof(len), sum);
	sum = bpf_csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

	// sum up payload
	__be32 *buf = (void *)icmp6;
	for (int i = 0; i < IPV6_MTU_MIN; i += 4) {
		if ((void *)(buf + 1) > data_end) {
			break;
		}
		sum = bpf_csum_diff(NULL, 0, buf, sizeof(*buf), sum);
		buf++;
	}

	// in case there are some bytes left because the packet length is not a
	// multiple of 4.
	if (data_end - (void *)buf > 0) {
		__u8 r[4];
		void *buf2 = (void *)buf;
		for (int i = 0; i < 4; i++) {
			r[i] = (void *)(buf2 + 1) > data_end ? 0 : *(__u8 *)buf2++;
		}
		sum = bpf_csum_diff(NULL, 0, (__be32*)&r, sizeof(__be32), sum);
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

static __always_inline void counter_increment(__u32 key) {
	__u32 *value = bpf_map_lookup_elem(&ttl_counters, &key);
	if (value) {
		__sync_fetch_and_add(value, 1);
	}
}

static __always_inline int reply_exceeded(struct xdp_md *ctx, struct in6_addr *src_addr) {
	void *data		= (void *)(unsigned long)ctx->data;
	void *data_end	= (void *)(unsigned long)ctx->data_end;
	int off			= 0;
	int len_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - (data_end - data);

	if (bpf_xdp_adjust_head(ctx, (0 - (int)ADD_HDR_LEN)) != 0)
		return XDP_DROP;

	if (len_adjust < 0)
		bpf_xdp_adjust_tail(ctx, len_adjust);

	// reinitialize after length change
	data		= (void *)(long)ctx->data;
	data_end	= (void *)(long)ctx->data_end;
	off			= 0;

	// validate locations after resizing
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + ADD_HDR_LEN > data_end)
		return XDP_DROP;

	// former header positions
	struct ethhdr *eth_o = data + (int)ADD_HDR_LEN;
	struct ipv6hdr *ipv6_o = data + (int)ADD_HDR_LEN + sizeof(*eth_o);

	// new headers
	struct ethhdr *eth_n = data;
	off += sizeof(struct ethhdr);

	// relocate data and swap mac addresses
	bpf_memcpy(eth_n->h_source, eth_o->h_dest, ETH_ALEN);
	bpf_memcpy(eth_n->h_dest, eth_o->h_source, ETH_ALEN);
	eth_n->h_proto = eth_o->h_proto;

	struct ipv6hdr *ipv6_n = data + off;
	off += sizeof(struct ipv6hdr);

	__u16 payload_len = data_end - data - off;

	ipv6_n->version		= 6;
	ipv6_n->priority	= ipv6_o->priority;
	ipv6_n->payload_len = bpf_htons(payload_len);
	ipv6_n->nexthdr		= IPPROTO_ICMPV6;
	ipv6_n->hop_limit	= 64;
	ipv6_n->saddr		= *src_addr;
	ipv6_n->daddr		= ipv6_o->saddr;
	bpf_memcpy(ipv6_n->flow_lbl, ipv6_o->flow_lbl, sizeof(ipv6_n->flow_lbl));

	struct icmp6hdr *icmp6 = data + off;

	icmp6->icmp6_type					= ICMP6_TIME_EXCEEDED;
	icmp6->icmp6_code					= 0;
	icmp6->icmp6_cksum					= 0;
	// time exceeded has 4 bytes inused space before payload starts
	icmp6->icmp6_dataun.un_data32[0]	= 0;

	icmp6->icmp6_cksum = icmp6_csum(icmp6, ipv6_n, data_end);

	return XDP_TX;
}

SEC("xdp")
int xdp_ttltogo(struct xdp_md *ctx) {
	void *data		= (void *)(unsigned long)ctx->data;
	void *data_end	= (void *)(unsigned long)ctx->data_end;
	int off			= 0;

	counter_increment(TTL_COUNTER_KEY_ENTRY);

	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return DEFAULT_ACTION;

	struct ethhdr *eth = data;
	off += sizeof(*eth);

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_IPV6);

	struct ipv6hdr *ipv6 = data + off;
	off += sizeof(*ipv6);

	// key 0 is special an has the target address we are watching for
	__u32 target_key = 0;
	struct in6_addr *target = bpf_map_lookup_elem(&ttl_addrs, &target_key);

	if (!target)
		return DEFAULT_ACTION;

	if (!IN6_ARE_ADDR_EQUAL(&ipv6->daddr, target))
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_TARGET);

	// all other entries are the addressess we want to answer with for the
	// specific hop limit
	__u32 hop_key = ipv6->hop_limit;
	struct in6_addr *ttl_addr = bpf_map_lookup_elem(&ttl_addrs, &hop_key);

	if (!ttl_addr || !((const uint32_t *) (ttl_addr))[0])
		return DEFAULT_ACTION;

	counter_increment(TTL_COUNTER_KEY_FOUND);

	return reply_exceeded(ctx, ttl_addr);
}

char _license[] SEC("license") = "GPL";
