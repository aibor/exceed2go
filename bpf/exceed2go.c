// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "types.h"
#include "bpf.h"
#include "ether.h"
#include "ip6.h"
#include "icmp6.h"
#include "libbpf/bpf_endian.h"
#include "libbpf/bpf_helpers.h"

#define MAX_ADDRS 256

#define ADJ_LEN (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

/* Definition of hop addresses in the order they are traversed by the packet.
 * 0 is an invalid hop number. Last entry is the actual target address.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, MAX_ADDRS);
} exceed2go_addrs SEC(".maps");

enum counter_key {
  COUNTER_IPV6_PACKET,
  COUNTER_TO_TARGET,
  COUNTER_ICMP_PACKET,
  COUNTER_ICMP_ECHO_REQUEST,
  COUNTER_ICMP_CORRECT_CHECKSUM,
  COUNTER_PKT_UNRELATED,
  COUNTER_PKT_HOP_FOUND,
  COUNTER_PKT_ECHO_REQUEST,
  COUNTER_DO_REDIRECT,
  COUNTER_MAX_ENTRIES,
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, enum counter_key);
  __type(value, __u32);
  __uint(max_entries, COUNTER_MAX_ENTRIES);
} exceed2go_counters SEC(".maps");

static __always_inline void
count(const enum counter_key key) {
  __u32 *value = bpf_map_lookup_elem(&exceed2go_counters, &key);
  if (likely(value))
    __sync_fetch_and_add(value, 1);
}

enum base_layer {
  BASE_LAYER_L2,
  BASE_LAYER_L3,
};

enum pkt_status {
  PKT_UNRELATED,
  PKT_HOP_FOUND,
  PKT_ECHO_REQUEST,
};

struct pkt_info {
  struct ethhdr  *eth;
  struct ipv6hdr *ipv6;
  void           *end;
  struct in6_addr reply_saddr;
  struct in6_addr reply_daddr;
  int             tail_adjust;
};

static __always_inline void
pkt_info_set_ptrs(struct pkt_info      *pkt,
                  const __u32           start,
                  const __u32           end,
                  const enum base_layer base_layer) {
  switch (base_layer) {
  case BASE_LAYER_L2:
    pkt->eth  = (void *)(unsigned long)start;
    pkt->ipv6 = next_header(pkt->eth);
    break;
  case BASE_LAYER_L3:
    pkt->ipv6 = (void *)(unsigned long)start;
    break;
  }
  pkt->end = (void *)(unsigned long)end;
}

static __always_inline __u32
search_hop(const struct in6_addr *needle) {
  __u32 hop;

  /* 0 is an invalid hop number, so skip it. */
  bpf_for(hop, 1, MAX_ADDRS) {
    struct in6_addr *value = bpf_map_lookup_elem(&exceed2go_addrs, &hop);
    if (!value)
      break;

    /* Exit from the iteration if the address is found. */
    if (in6_addr_equal(needle, value))
      return hop;
  }

  /* 0 is invalid hop number and indicates no key found. */
  return 0;
}

/* Calculate if the packet end needs to be adjusted. It must not be longer than
 * the IPv6 minimum MTU and should always be a multiple of 4 bytes long so it
 * works with our check sum implementation. Returns a signed value that can be
 * passed to bpf_xdp_adjust_tail and bpf_skb_change_tail.
 */
static __always_inline int
tail_adjust(int ipv6_pkt_len) {
  /* The ICMP time exceeded packet may not be longer than IPv6 minimum MTU. */
  __u32 new_ip_pkt_len = ADJ_LEN + ipv6_pkt_len;
  int   tail_adj       = IPV6_MTU_MIN - new_ip_pkt_len;

  /* Ensure the resulting packet is always a multiple of 4 so it works with the
   * check sum implementation.
   */
  if (tail_adj > 0 && new_ip_pkt_len % 4)
    tail_adj = -(new_ip_pkt_len % 4);

  return tail_adj < 0 ? tail_adj : 0;
}

/* Create a ICMPv6 time exceeded message for the current packet and send it
 * from the given src_addr.
 */
static __always_inline void
exceed2go_exceeded(struct pkt_info *pkt) {
  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);

  ipv6_init(pkt->ipv6,
            bpf_htons(pkt->end - (void *)icmp6),
            IPPROTO_ICMPV6,
            &pkt->reply_saddr,
            &pkt->reply_daddr);

  icmp6->icmp6_type                = ICMP6_TIME_EXCEEDED;
  icmp6->icmp6_code                = 0;
  icmp6->icmp6_cksum               = 0;
  icmp6->icmp6_dataun.un_data32[0] = 0;

  __wsum csum = 0;
  csum        = ipv6_pseudo_hdr_csum(pkt->ipv6, csum);
  csum        = pkt_csum(icmp6, pkt->end, true, csum);

  icmp6->icmp6_cksum = ~csum_fold(csum);
}

/* Create ICMPv6 echo reply message for the given packet. */
static __always_inline void
exceed2go_echo(struct pkt_info *pkt) {
  /* Reset fields but keep payload_len. Gets optimized by the compiler so the
   * payload_length field is kept as is.
   * */
  ipv6_init(pkt->ipv6,
            pkt->ipv6->payload_len,
            IPPROTO_ICMPV6,
            &pkt->reply_saddr,
            &pkt->reply_daddr);

  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);
  icmp6->icmp6_type      = ICMP6_ECHO_REPLY;
  icmp6->icmp6_code      = 0;

  /* Only field changed that affects the check sum field is the ICMP type. */
  icmp6->icmp6_cksum += ICMP6_ECHO_REQUEST - ICMP6_ECHO_REPLY;
}

/* Parse packet for a known address.
 *
 * Returns the status and may modify the given pkt_info as following:
 *   - PKT_UNRELATED if the destination address is not in the address map.
 *   - PKT_HOP_FOUND if the packet's hop_limit is low enough. In this case the
 *     pkt_info->exceed_addr pointer will be set to to the address that we want
 *     to send a time exceed packet from.
 *   - PKT_ECHO_REQUEST if the hop limit is not low enough and the packet is an
 *     ICMP echo request.
 */
static __always_inline enum pkt_status
parse_packet(struct pkt_info *pkt, const enum base_layer base_layer) {
  assert_boundary(pkt->ipv6, pkt->end, PKT_UNRELATED);

  if (base_layer == BASE_LAYER_L2)
    assert(pkt->eth->proto == bpf_htons(ETH_P_IPV6), PKT_UNRELATED);

  assert(pkt->ipv6->version == 6, PKT_UNRELATED);
  count(COUNTER_IPV6_PACKET);

  __u32 addr_hop = search_hop(&pkt->ipv6->daddr);

  /* If the address is found (has hop > 0), we continue and will reply with an
   * ICMPv6 time-exceeded message if the hop limit is low enough, or reply to
   * echo requests.
   */
  assert(addr_hop, PKT_UNRELATED);
  count(COUNTER_TO_TARGET);

  /* Only reply with time exceeded messages, if the hop_limit is not above the
   * index of the destination address. All the addresses above should be ignored
   * as the destination has already been reached so all addrs after are not
   * relevant.
   */
  __u32 hop_key = pkt->ipv6->hop_limit;
  if (addr_hop > hop_key) {
    struct in6_addr *exceed_addr =
        bpf_map_lookup_elem(&exceed2go_addrs, &hop_key);

    if (exceed_addr != NULL) {
      pkt->tail_adjust = tail_adjust(pkt->end - (void *)pkt->ipv6);
      in6_addr_copy(&pkt->reply_saddr, exceed_addr);
      in6_addr_copy(&pkt->reply_daddr, &pkt->ipv6->saddr);
      return PKT_HOP_FOUND;
    }
  }

  /* If the address was found but does not match our exceed requirements, check
   * if it is an ICMP echo request that we want to reply to.
   */
  assert(pkt->ipv6->nexthdr == IPPROTO_ICMPV6, PKT_UNRELATED);
  count(COUNTER_ICMP_PACKET);

  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);
  assert_boundary(icmp6, pkt->end, PKT_UNRELATED);

  assert(icmp6->icmp6_type == ICMP6_ECHO_REQUEST, PKT_UNRELATED);
  assert(icmp6->icmp6_code == 0, PKT_UNRELATED);
  count(COUNTER_ICMP_ECHO_REQUEST);

  /* Validate check sum. */
  __wsum csum = 0;
  csum        = ipv6_pseudo_hdr_csum(pkt->ipv6, csum);
  csum        = pkt_csum(icmp6, pkt->end, true, csum);

  assert(csum_fold(csum) == 0xffff, PKT_UNRELATED);
  count(COUNTER_ICMP_CORRECT_CHECKSUM);

  in6_addr_copy(&pkt->reply_saddr, &pkt->ipv6->daddr);
  in6_addr_copy(&pkt->reply_daddr, &pkt->ipv6->saddr);

  return PKT_ECHO_REQUEST;
}

static __always_inline int
exceed2go_xdp(struct xdp_md *ctx) {
  /* L3 interfaces do not support XDP and L3 interfaces are not supported in
   * generic mode. It always expects an ethernet header:
   * https://github.com/torvalds/linux/blob/04b8076df2534f08bb4190f90a24e0f7f8930aca/net/core/dev.c#L4891
   */
  enum base_layer base_layer = BASE_LAYER_L2;

  struct pkt_info pkt = {0};
  pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

  switch (parse_packet(&pkt, base_layer)) {
  case PKT_UNRELATED:
    count(COUNTER_PKT_UNRELATED);
    return XDP_PASS;
  case PKT_HOP_FOUND:
    count(COUNTER_PKT_HOP_FOUND);

    /* Make room for additional headers. */
    assert(bpf_xdp_adjust_head(ctx, -(int)ADJ_LEN) == 0, XDP_ABORTED);

    /* Adjust packet length to match length requirements. */
    int tail_adj = pkt.tail_adjust;
    assert(bpf_xdp_adjust_tail(ctx, tail_adj) == 0, XDP_ABORTED);

    /* Reinitialize after length change. */
    pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

    /* Move and reverse Ethernet header before it gets overwritten by new IPv6
     * header.
     */
    struct ethhdr *old_eth = (void *)pkt.eth + (int)ADJ_LEN;
    assert_boundary(old_eth, pkt.end, XDP_ABORTED);

    eth_hdr_reverse(pkt.eth, old_eth);
    exceed2go_exceeded(&pkt);

    break;
  case PKT_ECHO_REQUEST:
    count(COUNTER_PKT_ECHO_REQUEST);

    eth_hdr_reverse(pkt.eth, pkt.eth);
    exceed2go_echo(&pkt);

    break;
  }

  count(COUNTER_DO_REDIRECT);

  return XDP_TX;
}

static __always_inline int
exceed2go_tc(struct __sk_buff *ctx, const enum base_layer base_layer) {
  struct pkt_info pkt = {0};
  struct ethhdr   eth;

  pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

  switch (parse_packet(&pkt, base_layer)) {
  case PKT_UNRELATED:
    count(COUNTER_PKT_UNRELATED);
    return TC_ACT_UNSPEC;
  case PKT_HOP_FOUND:
    count(COUNTER_PKT_HOP_FOUND);

    /* bpf_skb_adjust_room overwrites the Ethernet header, so store it so we can
     * rewrite it later.
     */
    if (base_layer == BASE_LAYER_L2)
      memcpy(&eth, pkt.eth, sizeof(struct ethhdr));

    /* Make room for additional headers.
     * bpf_skb_adjust_room requires skb->protocol to be set to ETH_P_IP or
     * ETH_P_IPV6, otherwise it returns ENOTSUPP. Since this can't be set in
     * test run input, test must use an actual interface.
     */
    long rc_head_adj;
    if (ctx->protocol == bpf_htons(ETH_P_IPV6)) {
      rc_head_adj = bpf_skb_adjust_room(ctx,
                                        (s32)ADJ_LEN,
                                        (u32)BPF_ADJ_ROOM_MAC,
                                        (u64)BPF_F_ADJ_ROOM_FIXED_GSO);
    } else {
      /* fallback in case the protocol is not set, like when testing layer 3
       * interfaces.
       */
      rc_head_adj = bpf_skb_change_head(ctx, (u32)ADJ_LEN, 0);
    }
    assert(rc_head_adj == 0, TC_ACT_SHOT);

    /* Adjust packet length to match length requirements. */
    int new_len = ctx->len + pkt.tail_adjust;
    assert(bpf_skb_change_tail(ctx, new_len, 0) == 0, TC_ACT_SHOT);

    /* Reinitialize after length change. */
    pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);
    struct icmp6hdr *icmp6 = next_header(pkt.ipv6);
    assert_boundary(icmp6, pkt.end, TC_ACT_SHOT);

    /* Restore and reverse Ethernet header. */
    if (base_layer == BASE_LAYER_L2)
      eth_hdr_reverse(pkt.eth, &eth);

    exceed2go_exceeded(&pkt);

    break;
  case PKT_ECHO_REQUEST:
    count(COUNTER_PKT_ECHO_REQUEST);

    if (base_layer == BASE_LAYER_L2)
      eth_hdr_reverse(pkt.eth, pkt.eth);

    exceed2go_echo(&pkt);

    break;
  }

  count(COUNTER_DO_REDIRECT);

  return bpf_redirect(ctx->ifindex, 0);
}

SEC("xdp")
int
exceed2go_xdp_l2(struct xdp_md *ctx) {
  return exceed2go_xdp(ctx);
}

SEC("tc")
int
exceed2go_tc_l2(struct __sk_buff *ctx) {
  return exceed2go_tc(ctx, BASE_LAYER_L2);
}

SEC("tc")
int
exceed2go_tc_l3(struct __sk_buff *ctx) {
  return exceed2go_tc(ctx, BASE_LAYER_L3);
}

char _license[] SEC("license") = "GPL";
