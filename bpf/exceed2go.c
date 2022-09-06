#include "btf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_ACTION XDP_PASS
#define ETH_ALEN 6
#define ETH_TLEN 2
#define ETH_P_IPV6 0x86DD
#define IPV6_MTU_MIN 1280
#define IPV6_ALEN 16
#define IPPROTO_ICMPV6 58
#define ICMP6_TIME_EXCEEDED 3
#define ADD_HDR_LEN (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define bpf_memcpy __builtin_memcpy

#define IN6_ARE_ADDR_EQUAL(a, b)                                               \
  ((((const uint32_t *)(a))[0] == ((const uint32_t *)(b))[0]) &&               \
   (((const uint32_t *)(a))[1] == ((const uint32_t *)(b))[1]) &&               \
   (((const uint32_t *)(a))[2] == ((const uint32_t *)(b))[2]) &&               \
   (((const uint32_t *)(a))[3] == ((const uint32_t *)(b))[3]))

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 32);
} exceed_addrs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 8);
} exceed_counters SEC(".maps");

enum exceed_counter_key {
  COUNTER_KEY_IPV6,
  COUNTER_KEY_TARGET,
  COUNTER_KEY_FOUND,
  COUNTER_KEY_DROP
};

static __always_inline __u16 csum_fold(__u32 sum) {
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)~sum;
}

static __always_inline __u32 icmp6_csum(struct icmp6hdr *icmp6,
                                        struct ipv6hdr *ipv6, void *data_end) {
  // value already network byte order
  __be32 len = ((__u32)ipv6->payload_len) << 16;
  __be32 nexthdr = ((__u32)ipv6->nexthdr) << 24;
  __be32 sum = 0;

  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->saddr, IPV6_ALEN, sum);
  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->daddr, IPV6_ALEN, sum);
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
    sum = bpf_csum_diff(NULL, 0, (__be32 *)&r, sizeof(__be32), sum);
  }

  return sum;
}

static __always_inline void counter_increment(__u32 key) {
  __u32 *value = bpf_map_lookup_elem(&exceed_counters, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline int reply_exceeded(struct xdp_md *ctx,
                                          struct in6_addr *src_addr) {
  volatile void *data, *data_end;
  struct ethhdr *eth, *orig_eth;
  struct ipv6hdr *ipv6, *orig_ipv6;
  struct icmp6hdr *icmp6;
  int tail_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - (ctx->data_end - ctx->data);

  if (bpf_xdp_adjust_head(ctx, (0 - (int)ADD_HDR_LEN)) != 0)
    return XDP_DROP;

  if (tail_adjust < 0)
    bpf_xdp_adjust_tail(ctx, tail_adjust);

  // reinitialize after length change
  data = (void *)(unsigned long)ctx->data;
  data_end = (void *)(unsigned long)ctx->data_end;

  // former header positions
  orig_eth = (void *)data + (int)ADD_HDR_LEN;
  orig_ipv6 = (void *)(orig_eth + 1);

  // new headers
  eth = (void *)data;
  ipv6 = (void *)(eth + 1);
  if ((void *)(orig_ipv6 + 1) > data_end)
    return XDP_DROP;

  // relocate data and swap mac addresses
  bpf_memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
  bpf_memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
  eth->h_proto = orig_eth->h_proto;

  icmp6 = (void *)(ipv6 + 1);

  __u16 payload_len = data_end - (void *)icmp6;

  ipv6->version = 6;
  ipv6->priority = orig_ipv6->priority;
  ipv6->payload_len = bpf_htons(payload_len);
  ipv6->nexthdr = IPPROTO_ICMPV6;
  ipv6->hop_limit = 64;
  ipv6->saddr = *src_addr;
  ipv6->daddr = orig_ipv6->saddr;
  bpf_memcpy(ipv6->flow_lbl, orig_ipv6->flow_lbl, sizeof(ipv6->flow_lbl));

  icmp6->icmp6_type = ICMP6_TIME_EXCEEDED;
  icmp6->icmp6_code = 0;
  // set checksum to zero for calculation
  icmp6->icmp6_cksum = 0;
  // time exceeded has 4 bytes inused space before payload starts
  icmp6->icmp6_dataun.un_data32[0] = 0;

  icmp6->icmp6_cksum = csum_fold(icmp6_csum(icmp6, ipv6, (void *)data_end));

  return XDP_TX;
}

SEC("xdp")
int exceed2go(struct xdp_md *ctx) {
  volatile void *data, *data_end;
  volatile struct ethhdr *eth;
  volatile struct ipv6hdr *ipv6;
  int ret = DEFAULT_ACTION;

  data = (void *)(unsigned long)ctx->data;
  data_end = (void *)(unsigned long)ctx->data_end;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return ret;

  if (eth->h_proto != bpf_htons(ETH_P_IPV6))
    return ret;

  counter_increment(COUNTER_KEY_IPV6);

  ipv6 = (void *)(eth + 1);
  if ((void *)(ipv6 + 1) > data_end)
    return ret;

  // key 0 is special an has the target address we are watching for
  __u32 target_key = 0;
  struct in6_addr *target = bpf_map_lookup_elem(&exceed_addrs, &target_key);

  if (!target)
    return ret;

  if (!IN6_ARE_ADDR_EQUAL(&ipv6->daddr, target))
    return ret;

  counter_increment(COUNTER_KEY_TARGET);

  // all other entries are the addressess we want to answer with for the
  // specific hop limit
  __u32 hop_key = ipv6->hop_limit;
  struct in6_addr *exceed_addr = bpf_map_lookup_elem(&exceed_addrs, &hop_key);

  if (exceed_addr && ((const uint32_t *)(exceed_addr))[0]) {
    counter_increment(COUNTER_KEY_FOUND);
    ret = reply_exceeded(ctx, exceed_addr);
  }

  if (ret == XDP_DROP)
    counter_increment(COUNTER_KEY_DROP);

  return ret;
}

char _license[] SEC("license") = "GPL";
