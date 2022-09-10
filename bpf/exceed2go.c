#include "btf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_ACTION      XDP_PASS
#define ETH_ALEN            6
#define ETH_TLEN            2
#define ETH_P_IPV6          0x86DD
#define IPV6_MTU_MIN        1280
#define IPV6_ALEN           16
#define IPV6_HOP_LIMIT      64
#define IPPROTO_ICMPV6      58
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_ECHO_REQUEST  128
#define ICMP6_ECHO_REPLY    129
#define ADD_HDR_LEN         (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define bpf_memcpy __builtin_memcpy

#define IN6_ARE_ADDR_EQUAL(a, b)                                               \
  ((((const __u32 *)(a))[0] == ((const __u32 *)(b))[0]) &&                     \
   (((const __u32 *)(a))[1] == ((const __u32 *)(b))[1]) &&                     \
   (((const __u32 *)(a))[2] == ((const __u32 *)(b))[2]) &&                     \
   (((const __u32 *)(a))[3] == ((const __u32 *)(b))[3]))

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
  COUNTER_KEY_DROP,
  COUNTER_KEY_TARGET_ICMP,
  COUNTER_KEY_TARGET_ICMP_ECHO_REQ,
};

static __always_inline void counter_increment(__u32 key) {
  __u32 *value = bpf_map_lookup_elem(&exceed_counters, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline __u16 csum_fold(__u32 sum) {
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)~sum;
}

static __always_inline __u32 icmp6_csum(volatile struct icmp6hdr *icmp6,
                                        volatile struct ipv6hdr  *ipv6,
                                        volatile void            *data_end) {
  /* Value is already in network byte order. */
  __be32 len     = ((__u32)ipv6->payload_len) << 16;
  __be32 nexthdr = ((__u32)ipv6->nexthdr) << 24;
  __be32 sum     = 0;

  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->saddr, IPV6_ALEN, sum);
  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->daddr, IPV6_ALEN, sum);
  sum = bpf_csum_diff(NULL, 0, &len, sizeof(len), sum);
  sum = bpf_csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

  /* Sum up payload. */
  __be32 *buf = (void *)icmp6;
  for (int i = 0; i < IPV6_MTU_MIN; i += 4) {
    if ((void *)(buf + 1) > data_end) {
      break;
    }
    sum = bpf_csum_diff(NULL, 0, buf, sizeof(*buf), sum);
    buf++;
  }

  /* In case there are some bytes left because the packet length is not a
   * multiple of 4.
   */
  if (data_end - (void *)buf > 0) {
    __u8  r[4];
    void *buf2 = (void *)buf;
    for (int i = 0; i < 4; i++) {
      r[i] = (void *)(buf2 + 1) > data_end ? 0 : *(__u8 *)buf2++;
    }
    sum = bpf_csum_diff(NULL, 0, (__be32 *)&r, sizeof(__be32), sum);
  }

  return sum;
}

static __always_inline int reply_exceeded(struct xdp_md   *ctx,
                                          struct in6_addr *src_addr) {
  volatile void   *data, *data_end;
  struct ethhdr   *eth, *orig_eth;
  struct ipv6hdr  *ipv6, *orig_ipv6;
  struct icmp6hdr *icmp6;

  /* The ICMP time exceeded packet may not be longer than IPv6 minimum MTU.
   * TODO: add test case
   */
  int tail_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - (ctx->data_end - ctx->data);

  if (bpf_xdp_adjust_head(ctx, (0 - (int)ADD_HDR_LEN)) != 0)
    return XDP_DROP;

  if (tail_adjust < 0)
    bpf_xdp_adjust_tail(ctx, tail_adjust);

  /* Reinitialize after length change. */
  data     = (void *)(unsigned long)ctx->data;
  data_end = (void *)(unsigned long)ctx->data_end;

  /* Initialize former header positions. */
  orig_eth  = (void *)data + (int)ADD_HDR_LEN;
  orig_ipv6 = (void *)(orig_eth + 1);

  /* Initialize new headers. */
  eth  = (void *)data;
  ipv6 = (void *)(eth + 1);
  if ((void *)(orig_ipv6 + 1) > data_end)
    return XDP_DROP;

  /* Relocate data and swap mac addresses. */
  bpf_memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
  bpf_memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
  eth->h_proto = orig_eth->h_proto;

  icmp6 = (void *)(ipv6 + 1);

  __u16 payload_len = data_end - (void *)icmp6;

  ipv6->version     = 6;
  ipv6->priority    = 0;
  ipv6->flow_lbl[0] = 0;
  ipv6->flow_lbl[1] = 1;
  ipv6->flow_lbl[2] = 2;
  ipv6->payload_len = bpf_htons(payload_len);
  ipv6->nexthdr     = IPPROTO_ICMPV6;
  ipv6->hop_limit   = IPV6_HOP_LIMIT;
  ipv6->saddr       = *src_addr;
  ipv6->daddr       = orig_ipv6->saddr;

  icmp6->icmp6_type                = ICMP6_TIME_EXCEEDED;
  icmp6->icmp6_code                = 0;
  /* Set checksum to zero for calculation. */
  icmp6->icmp6_cksum               = 0;
  /* Time exceeded has 4 bytes inused space before payload starts. */
  icmp6->icmp6_dataun.un_data32[0] = 0;

  icmp6->icmp6_cksum = csum_fold(icmp6_csum(icmp6, ipv6, (void *)data_end));

  return XDP_TX;
}

static __always_inline int reply_echo(volatile struct ethhdr   *eth,
                                      volatile struct ipv6hdr  *ipv6,
                                      volatile struct icmp6hdr *icmp6,
                                      volatile void            *data_end) {

  /* Swap ethernet addresses. */
  char tmphwaddr[ETH_ALEN];
  bpf_memcpy(tmphwaddr, (const void *)&eth->h_source, ETH_ALEN);
  bpf_memcpy((void *)eth->h_source, (const void *)&eth->h_dest, ETH_ALEN);
  bpf_memcpy((void *)eth->h_dest, tmphwaddr, ETH_ALEN);

  /* Swap IPv6 addresses. */
  struct in6_addr tmpipv6addr = ipv6->saddr;
  ipv6->saddr                 = ipv6->daddr;
  ipv6->daddr                 = tmpipv6addr;
  ipv6->hop_limit             = IPV6_HOP_LIMIT;

  /* Set echo reply header. */
  icmp6->icmp6_type  = ICMP6_ECHO_REPLY;
  icmp6->icmp6_code  = 0;
  icmp6->icmp6_cksum = 0;

  icmp6->icmp6_cksum = csum_fold(icmp6_csum(icmp6, ipv6, (void *)data_end));

  return XDP_TX;
}

SEC("xdp")
int exceed2go(struct xdp_md *ctx) {
  int ret = DEFAULT_ACTION;

  volatile void *data     = (void *)(unsigned long)ctx->data;
  volatile void *data_end = (void *)(unsigned long)ctx->data_end;

  volatile struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    goto end;

  if (eth->h_proto != bpf_htons(ETH_P_IPV6))
    goto end;

  counter_increment(COUNTER_KEY_IPV6);

  volatile struct ipv6hdr *ipv6 = (void *)(eth + 1);
  if ((void *)(ipv6 + 1) > data_end)
    goto end;

  /* Key 0 is special an has the target address we are watching for. */
  __u32            target_key = 0;
  struct in6_addr *target     = bpf_map_lookup_elem(&exceed_addrs, &target_key);

  if (!target || !IN6_ARE_ADDR_EQUAL(&ipv6->daddr, target))
    goto end;

  counter_increment(COUNTER_KEY_TARGET);

  /* All other entries are the addressess we want to answer with for the
   * specific hop limit.
   */
  __u32            hop_key     = ipv6->hop_limit;
  struct in6_addr *exceed_addr = bpf_map_lookup_elem(&exceed_addrs, &hop_key);

  /* If there is an address found for the hop limit then reply with ICMP time
   * exceeded message.
   */
  if (exceed_addr && ((const __u32 *)(exceed_addr))[0]) {
    counter_increment(COUNTER_KEY_FOUND);
    ret = reply_exceeded(ctx, exceed_addr);
    goto end;
  }

  if (ipv6->nexthdr != IPPROTO_ICMPV6)
    goto end;

  counter_increment(COUNTER_KEY_TARGET_ICMP);

  volatile struct icmp6hdr *icmp6 = (void *)(ipv6 + 1);
  if ((void *)(icmp6 + 1) > data_end)
    goto end;

  if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST)
    goto end;

  counter_increment(COUNTER_KEY_TARGET_ICMP_ECHO_REQ);

  ret = reply_echo(eth, ipv6, icmp6, data_end);

end:
  if (ret == XDP_DROP)
    counter_increment(COUNTER_KEY_DROP);

  return ret;
}

char _license[] SEC("license") = "GPL";
