#include "btf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_ACTION XDP_PASS
#define MAX_ADDRS      32

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
#define NEXT_HDR(h) ((void *)(h + 1))
#define CHECK_BOUNDARY(h, end, ret)                                            \
  if (NEXT_HDR(h) > end) {                                                     \
    return ret;                                                                \
  }

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, MAX_ADDRS);
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
  COUNTER_KEY_ICMP,
  COUNTER_KEY_ICMP_ECHO_REQ,
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

static __always_inline __u32 icmp6_csum(struct icmp6hdr *icmp6,
                                        struct ipv6hdr *ipv6, void *data_end) {
  /* Value is already in network byte order. */
  __be32 len     = ((__u32)ipv6->payload_len) << 16;
  __be32 nexthdr = ((__u32)ipv6->nexthdr) << 24;
  __be32 sum     = 0;

  /* Sum up IPv6 pseudo header. */
  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->saddr, IPV6_ALEN, sum);
  sum = bpf_csum_diff(NULL, 0, (__be32 *)&ipv6->daddr, IPV6_ALEN, sum);
  sum = bpf_csum_diff(NULL, 0, &len, sizeof(len), sum);
  sum = bpf_csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), sum);

  /* Sum up ICMP6 header and payload. */
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
  /* The ICMP time exceeded packet may not be longer than IPv6 minimum MTU.
   * TODO: add test case
   */
  int tail_adjust = IPV6_MTU_MIN - ADD_HDR_LEN - (ctx->data_end - ctx->data);

  if (bpf_xdp_adjust_head(ctx, (0 - (int)ADD_HDR_LEN)) != 0)
    return XDP_DROP;

  if (tail_adjust < 0)
    bpf_xdp_adjust_tail(ctx, tail_adjust);

  /* Reinitialize after length change. */
  void *data     = (void *)(unsigned long)ctx->data;
  void *data_end = (void *)(unsigned long)ctx->data_end;

  /* Initialize former header positions. */
  struct ethhdr  *orig_eth  = (void *)data + (int)ADD_HDR_LEN;
  struct ipv6hdr *orig_ipv6 = NEXT_HDR(orig_eth);
  CHECK_BOUNDARY(orig_ipv6, data_end, XDP_DROP);

  /* Initialize new headers. */
  struct ethhdr  *eth  = (void *)data;
  struct ipv6hdr *ipv6 = NEXT_HDR(eth);

  /* Relocate data and swap mac addresses. */
  bpf_memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
  bpf_memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
  eth->h_proto = orig_eth->h_proto;

  /* Create new ICMP6 layer. */
  struct icmp6hdr *icmp6 = NEXT_HDR(ipv6);

  __u16 payload_len = data_end - (void *)icmp6;

  ipv6->version     = 6;
  ipv6->priority    = 0;
  ipv6->flow_lbl[0] = 0;
  ipv6->flow_lbl[1] = 0;
  ipv6->flow_lbl[2] = 0;
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

static __always_inline int reply_echo(struct ethhdr *eth, struct ipv6hdr *ipv6,
                                      struct icmp6hdr *icmp6, void *data_end) {

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
  void *data     = (void *)(unsigned long)ctx->data;
  void *data_end = (void *)(unsigned long)ctx->data_end;

  struct ethhdr *eth = data;
  CHECK_BOUNDARY(eth, data_end, DEFAULT_ACTION);

  if (eth->h_proto != bpf_htons(ETH_P_IPV6))
    return DEFAULT_ACTION;

  counter_increment(COUNTER_KEY_IPV6);

  struct ipv6hdr *ipv6 = NEXT_HDR(eth);
  CHECK_BOUNDARY(ipv6, data_end, DEFAULT_ACTION);

  struct in6_addr *target = NULL;
  __u32            target_key;
  for (__u32 i = 0; i < MAX_ADDRS; i++) {
    /* Verifier doesn't like pointer to the loop var. */
    target_key = i;
    target     = bpf_map_lookup_elem(&exceed_addrs, &target_key);

    /* If lookup returns nothing or found address is zero exit as that indicates
     *we are through the list of configured addresses.
     */
    if (!target || !((const __u32 *)(target))[0])
      return DEFAULT_ACTION;

    if (IN6_ARE_ADDR_EQUAL(&ipv6->daddr, target))
      /* Found the destination address in our list. Break the loop and proceed
       * with the found target address.
       */
      break;

    target = NULL;
  }

  if (!target)
    return DEFAULT_ACTION;

  counter_increment(COUNTER_KEY_TARGET);

  /* Address map array is 0 indexed, but the lowest hop_limit that will reach us
   * is 1, so decrement the hop_key by 1.
   */
  __u32 hop_key = ipv6->hop_limit > 0 ? ipv6->hop_limit - 1 : 0;

  /* Only reply with time exceeded messages, if the hop_limit is not above the
   * index of the destination address. All the addresses above should be ignored
   * as the destination has already been reached so all addrs after are not
   * relevant.
   */
  if (target_key > hop_key) {
    struct in6_addr *exceed_addr = bpf_map_lookup_elem(&exceed_addrs, &hop_key);

    /* If there is an address found for the hop limit then reply with ICMP time
     * exceeded message.
     */
    if (exceed_addr && ((const __u32 *)(exceed_addr))[0]) {
      counter_increment(COUNTER_KEY_FOUND);
      int ret = reply_exceeded(ctx, exceed_addr);
      if (ret == XDP_DROP)
        counter_increment(COUNTER_KEY_DROP);
      return ret;
    }
  }

  /* If the packet wasn't answered already with a time exceeded message, it
   * might be an ICMP echo request that should be answered for all of our addrs.
   */
  if (ipv6->nexthdr != IPPROTO_ICMPV6)
    return DEFAULT_ACTION;

  counter_increment(COUNTER_KEY_ICMP);

  struct icmp6hdr *icmp6 = NEXT_HDR(ipv6);
  CHECK_BOUNDARY(icmp6, data_end, DEFAULT_ACTION);

  if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST)
    return DEFAULT_ACTION;

  counter_increment(COUNTER_KEY_ICMP_ECHO_REQ);

  return reply_echo(eth, ipv6, icmp6, data_end);
}

char _license[] SEC("license") = "GPL";
