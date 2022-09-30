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
#define ADJ_LEN             (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define bpf_memcpy __builtin_memcpy
#define IN6_ARE_ADDR_EQUAL(a, b) \
  ((((const __u64 *)(a))[0] == ((const __u64 *)(b))[0]) && \
   (((const __u64 *)(a))[1] == ((const __u64 *)(b))[1]))
#define next_header(h) ((void *)(h + 1))
#define assert_boundary(h, end, ret) \
  if (next_header(h) > end) \
  return ret
#define assert_equal(f, e, ret) \
  if (f != e) \
  return ret

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
  COUNTER_KEY_ABORTED,
  COUNTER_KEY_ICMP,
  COUNTER_KEY_ICMP_ECHO_REQ,
};

static void counter_increment(__u32 key) {
  __u32 *value = bpf_map_lookup_elem(&exceed_counters, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

struct target_search_cb_ctx {
  struct in6_addr *needle;
  __u32            key;
  bool             found;
};

/* Callback function for bpf_for_each_map_elem for iterating over exceed_addrs
 * map looking up the given needle by the callback context struct.
 */
static long target_search_cb(void                        *map,
                             __u32                       *key,
                             struct in6_addr             *value,
                             struct target_search_cb_ctx *ctx) {
  /* If lookup returns nothing or found address is zero exit as that indicates
   *we are through the list of configured addresses.
   */
  if (!value || !((const __u32 *)(value))[0])
    return 1;

  if (IN6_ARE_ADDR_EQUAL(ctx->needle, value)) {
    /* Found the destination address in our list. Exit from the iteration. */
    ctx->found = true;
    ctx->key   = *key;

    return 1;
  }

  return 0;
}

/* Fold a 32bit integer checksum down to 16bit value as needed in protocol
 * headers.
 */
static __u16 csum_fold(__u32 sum) {
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)~sum;
}

/* Calculate ICMPv6 header checksum. This sums up the IPv6 pseudo header of the
 * given ipv6hdr struct, the ICMPv6 header and the payload.
 */
static __always_inline __u32 icmp6_csum(struct icmp6hdr *icmp6,
                                        struct ipv6hdr  *ipv6,
                                        void            *data_end) {
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

/* Create a ICMPv6 time exceeded message for the current packet and send it
 * from the given src_addr.
 */
static __always_inline int reply_exceeded(struct xdp_md   *ctx,
                                          struct in6_addr *src_addr) {
  /* The ICMP time exceeded packet may not be longer than IPv6 minimum MTU.
   * TODO: add test case
   */
  int tail_adjust = IPV6_MTU_MIN - ADJ_LEN - (ctx->data_end - ctx->data);

  assert_equal(bpf_xdp_adjust_head(ctx, (0 - (int)ADJ_LEN)), 0, XDP_ABORTED);

  if (tail_adjust < 0)
    bpf_xdp_adjust_tail(ctx, tail_adjust);

  /* Reinitialize after length change. */
  void *data     = (void *)(unsigned long)ctx->data;
  void *data_end = (void *)(unsigned long)ctx->data_end;

  /* Initialize former header positions. */
  struct ethhdr  *orig_eth  = (void *)data + (int)ADJ_LEN;
  struct ipv6hdr *orig_ipv6 = next_header(orig_eth);
  assert_boundary(orig_ipv6, data_end, XDP_ABORTED);

  /* Initialize new headers. */
  struct ethhdr  *eth  = (void *)data;
  struct ipv6hdr *ipv6 = next_header(eth);

  /* Relocate data and swap mac addresses. */
  bpf_memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
  bpf_memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
  eth->h_proto = orig_eth->h_proto;

  /* Create new ICMP6 layer. */
  struct icmp6hdr *icmp6 = next_header(ipv6);

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

/* Create ICMPv6 echo reply message for the given packet. */
static __always_inline int reply_echo(struct ethhdr   *eth,
                                      struct ipv6hdr  *ipv6,
                                      struct icmp6hdr *icmp6,
                                      void            *data_end) {

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
  assert_boundary(eth, data_end, DEFAULT_ACTION);
  assert_equal(eth->h_proto, bpf_htons(ETH_P_IPV6), DEFAULT_ACTION);
  counter_increment(COUNTER_KEY_IPV6);

  struct ipv6hdr *ipv6 = next_header(eth);
  assert_boundary(ipv6, data_end, DEFAULT_ACTION);

  /* Lookup the destination address in our address table. */
  struct target_search_cb_ctx target = {.needle = &ipv6->daddr, .found = false};
  bpf_for_each_map_elem(&exceed_addrs, target_search_cb, &target, 0);

  /* If the address is found, we continue and will reply with a ICMPv6
   * time-exceeded message if the hop limit is low enough, or reply to echo
   * requests.
   */
  assert_equal(target.found, true, DEFAULT_ACTION);
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
  if (target.key > hop_key) {
    struct in6_addr *exceed_addr = bpf_map_lookup_elem(&exceed_addrs, &hop_key);

    /* If there is an address found for the hop limit then reply with ICMP time
     * exceeded message.
     */
    if (exceed_addr && ((const __u32 *)(exceed_addr))[0]) {
      counter_increment(COUNTER_KEY_FOUND);
      int ret = reply_exceeded(ctx, exceed_addr);
      if (ret == XDP_ABORTED)
        counter_increment(COUNTER_KEY_ABORTED);
      return ret;
    }
  }

  /* If the packet wasn't answered already with a time exceeded message, it
   * might be an ICMP echo request that should be answered for all of our addrs.
   */
  assert_equal(ipv6->nexthdr, IPPROTO_ICMPV6, DEFAULT_ACTION);
  counter_increment(COUNTER_KEY_ICMP);

  struct icmp6hdr *icmp6 = next_header(ipv6);
  assert_boundary(icmp6, data_end, DEFAULT_ACTION);
  assert_equal(icmp6->icmp6_type, ICMP6_ECHO_REQUEST, DEFAULT_ACTION);
  counter_increment(COUNTER_KEY_ICMP_ECHO_REQ);

  return reply_echo(eth, ipv6, icmp6, data_end);
}

char _license[] SEC("license") = "GPL";
