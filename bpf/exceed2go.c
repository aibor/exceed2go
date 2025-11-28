// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "types.h"
#include "libbpf/bpf_endian.h"
#include "libbpf/bpf_helpers.h"

#define MAX_ADDRS 32

#define ETH_HLEN            14
#define ETH_ALEN            6
#define ETH_P_IPV6          0x86DD
#define IPV6_MTU_MIN        1280
#define IPV6_ALEN           16
#define IPV6_HOP_LIMIT      64
#define IPPROTO_ICMPV6      58
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_ECHO_REQUEST  128
#define ICMP6_ECHO_REPLY    129
#define ADJ_LEN             (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))

#define likely(p)      __builtin_expect(!!(p), 1)
#define unlikely(p)    __builtin_expect(!!(p), 0)
#define bpf_memcpy     __builtin_memcpy
#define next_header(h) ((void *)(h + 1))
#define assert_boundary(h, end, ret) \
  if (unlikely(next_header(h) > end)) \
  return ret
#define assert_equal(f, e, ret) \
  if (unlikely(f != e)) \
  return ret

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
  if (likely(value)) {
    __sync_fetch_and_add(value, 1);
  }
}

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

static __always_inline void
in6_addr_copy(struct in6_addr *dest, const struct in6_addr *src) {
  (dest->in6_u.u6_addr64[0] = src->in6_u.u6_addr64[0]);
  (dest->in6_u.u6_addr64[1] = src->in6_u.u6_addr64[1]);
}

static __always_inline bool
in6_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
  return ((a->in6_u.u6_addr64[0] == b->in6_u.u6_addr64[0]) &&
          (a->in6_u.u6_addr64[1] == b->in6_u.u6_addr64[1]));
}

/* Copy non address fields of the new headers. New headers are defined on stack
 * and make sure all fields that are not set dynamically later are initialized
 * with 0.
 */
static __always_inline void
ipv6_init(struct ipv6hdr *ipv6, const __be16 payload_len) {
  const struct ipv6hdr ipv6_new = {
      .version     = 6,
      .priority    = 0,
      .flow_lbl[0] = 0,
      .flow_lbl[1] = 0,
      .flow_lbl[2] = 0,
      .payload_len = payload_len,
      .nexthdr     = IPPROTO_ICMPV6,
      .hop_limit   = IPV6_HOP_LIMIT,
  };

  bpf_memcpy(ipv6, &ipv6_new, sizeof(struct ipv6hdr) - 2 * IPV6_ALEN);
}

struct target_search_cb_ctx {
  struct in6_addr needle;
  __u32           key;
  bool            found;
};

/* Callback function for bpf_for_each_map_elem for iterating over exceed_addrs
 * map looking up the given needle by the callback context struct.
 */
static long
target_search_cb(const void                  *map,
                 const __u32                 *key,
                 const struct in6_addr       *value,
                 struct target_search_cb_ctx *cb_ctx) {
  /* 0 is an invalid hop number, so skip it. */
  if (*key == 0) {
    return 0;
  }
  /* If lookup returns nothing or found address is zero exit as that indicates
   *we are through the list of configured addresses.
   */
  if (!value || !((const __u32 *)(value))[0])
    return 1;

  if (in6_addr_equal(&cb_ctx->needle, value)) {
    /* Found the destination address in our list. Exit from the iteration. */
    cb_ctx->found = true;
    cb_ctx->key   = *key;

    return 1;
  }

  return 0;
}

static __always_inline __wsum
csum_add(__wsum csum, __be32 addend) {
  csum += addend;
  return csum + (csum < addend);
}

/* Fold a 32bit integer checksum down to 16bit value as needed in protocol
 * headers.
 */
static __always_inline __sum16
csum_fold(__wsum sum) {
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)sum;
}

/* Calculate IPv6 pseudo header checksum with given initial value. */
static __always_inline __wsum
ipv6_pseudo_hdr_csum(const struct ipv6hdr *ipv6, __wsum sum) {
  sum = bpf_csum_diff(NULL, 0, (void *)&ipv6->saddr, 2 * IPV6_ALEN, sum);
  /* Payload_len is already in network byte order. */
  sum = csum_add(sum, ((__u32)ipv6->payload_len) << 16);
  sum = csum_add(sum, ((__u32)ipv6->nexthdr) << 24);
  return sum;
}

/* Calculate ICMPv6 header checksum. This sums up the IPv6 pseudo header of the
 * given ipv6hdr struct, the ICMPv6 header and the payload.
 */
static __always_inline __wsum
icmp6_csum(struct icmp6hdr *icmp6,
           void            *data_end,
           const bool       max4,
           __wsum           sum) {
  /* Sum up ICMP6 header and payload.
   * Walk in biggest possible chunks (bpf_csum_diff can take max 512 byte).
   * Packet size may not exceed IPV6_MTU_MIN + eth_hdr, so 1024 is biggest chunk
   * we need to process.
   */
  void *buf = icmp6;
  for (__u16 i = 1024; i > 4; i = (i > 512) ? (i - 512) : i >> 1) {
    __u16 j = (i >= 512) ? 512 : i;
    if (likely(buf + j <= data_end)) {
      sum = bpf_csum_diff(NULL, 0, buf, j, sum);
      buf += j;
    }
  }

  /* inline optimization. */
  if (likely(buf + 4 <= data_end)) {
    sum = csum_add(sum, *(__be32 *)buf++);
  }

  if (max4) {
    return sum;
  }

  __u32 addend = 0;
  if (likely(buf + 2 <= data_end)) {
    addend = *(__be16 *)buf++;
  }
  if (likely(buf + 1 <= data_end)) {
    addend += *(__u8 *)buf++;
  }
  sum = csum_add(sum, addend);

  return sum;
}

/* Swap ethernet addresses. */
static __always_inline void
eth_hdr_reverse(struct ethhdr *new, struct ethhdr *old) {
  struct mac_addr tmp;
  bpf_memcpy(&tmp, &old->daddr, sizeof(struct mac_addr));
  bpf_memcpy(&new->daddr, &old->saddr, sizeof(struct mac_addr));
  bpf_memcpy(&new->saddr, &tmp, sizeof(struct mac_addr));
  new->proto = old->proto;
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
  if (tail_adj > 0 && new_ip_pkt_len % 4) {
    tail_adj = -(new_ip_pkt_len % 4);
  }

  return tail_adj < 0 ? tail_adj : 0;
}

/* Create a ICMPv6 time exceeded message for the current packet and send it
 * from the given src_addr.
 */
static __always_inline bool
exceed2go_exceeded(struct pkt_info *pkt) {
  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);
  assert_boundary(icmp6, pkt->end, false);

  __be16 payload_len = bpf_htons(pkt->end - (void *)icmp6);
  ipv6_init(pkt->ipv6, payload_len);
  in6_addr_copy(&pkt->ipv6->saddr, &pkt->reply_saddr);
  in6_addr_copy(&pkt->ipv6->daddr, &pkt->reply_daddr);

  struct icmp6hdr icmp6_new = {0};
  icmp6_new.icmp6_type      = ICMP6_TIME_EXCEEDED;
  icmp6_new.icmp6_code      = 0;
  icmp6_new.icmp6_cksum     = 0;
  *icmp6                    = icmp6_new;

  __wsum csum        = 0;
  csum               = ipv6_pseudo_hdr_csum(pkt->ipv6, csum);
  csum               = icmp6_csum(icmp6, pkt->end, true, csum);
  icmp6->icmp6_cksum = ~csum_fold(csum);

  return true;
}

/* Create ICMPv6 echo reply message for the given packet. */
static __always_inline void
exceed2go_echo(struct pkt_info *pkt) {
  /* Reset fields but keep payload_len. Gets optimized by the compiler so the
   * payload_length field is kept as is.
   * */
  __be16 payload_len = pkt->ipv6->payload_len;
  ipv6_init(pkt->ipv6, payload_len);
  in6_addr_copy(&pkt->ipv6->saddr, &pkt->reply_saddr);
  in6_addr_copy(&pkt->ipv6->daddr, &pkt->reply_daddr);

  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);

  /* Set echo reply header. */
  icmp6->icmp6_type = ICMP6_ECHO_REPLY;
  icmp6->icmp6_code = 0;

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
  assert_boundary(pkt->ipv6, pkt->end, false);

  if (base_layer == BASE_LAYER_L2) {
    assert_equal(pkt->eth->proto, bpf_htons(ETH_P_IPV6), PKT_UNRELATED);
  }

  assert_equal(pkt->ipv6->version, 6, false);
  count(COUNTER_IPV6_PACKET);

  /* Lookup the destination address in our address table. */
  struct target_search_cb_ctx target = {
      .needle = pkt->ipv6->daddr,
      .found  = false,
  };
  bpf_for_each_map_elem(&exceed2go_addrs, target_search_cb, &target, 0);

  /* If the address is found, we continue and will reply with a ICMPv6
   * time-exceeded message if the hop limit is low enough, or reply to echo
   * requests.
   */
  assert_equal(target.found, true, PKT_UNRELATED);
  count(COUNTER_TO_TARGET);

  /* Only reply with time exceeded messages, if the hop_limit is not above the
   * index of the destination address. All the addresses above should be ignored
   * as the destination has already been reached so all addrs after are not
   * relevant.
   */
  __u32 hop_key = pkt->ipv6->hop_limit;
  if (target.key > hop_key) {
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
  assert_equal(pkt->ipv6->nexthdr, IPPROTO_ICMPV6, PKT_UNRELATED);
  count(COUNTER_ICMP_PACKET);

  struct icmp6hdr *icmp6 = next_header(pkt->ipv6);
  assert_boundary(icmp6, pkt->end, false);

  assert_equal(icmp6->icmp6_type, ICMP6_ECHO_REQUEST, PKT_UNRELATED);
  assert_equal(icmp6->icmp6_code, 0, false);
  count(COUNTER_ICMP_ECHO_REQUEST);

  /* Validate check sum. */
  __wsum csum = 0;
  csum        = ipv6_pseudo_hdr_csum(pkt->ipv6, csum);
  csum        = icmp6_csum(icmp6, pkt->end, true, csum);
  assert_equal(csum_fold(csum), 0xffff, PKT_UNRELATED);
  count(COUNTER_ICMP_CORRECT_CHECKSUM);

  in6_addr_copy(&pkt->reply_saddr, &pkt->ipv6->daddr);
  in6_addr_copy(&pkt->reply_daddr, &pkt->ipv6->saddr);

  return PKT_ECHO_REQUEST;
}

static __always_inline int
exceed2go_xdp(struct xdp_md *ctx, const enum base_layer base_layer) {
  struct pkt_info pkt = {0};

  pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

  switch (parse_packet(&pkt, base_layer)) {
  case PKT_UNRELATED:
    count(COUNTER_PKT_UNRELATED);
    return XDP_PASS;
  case PKT_HOP_FOUND:
    count(COUNTER_PKT_HOP_FOUND);
    /* Make room for additional headers. */
    assert_equal(bpf_xdp_adjust_head(ctx, -(int)ADJ_LEN), 0, XDP_ABORTED);
    /* Adjust packet length to match length requirements. */
    int tail_adj = pkt.tail_adjust;
    assert_equal(bpf_xdp_adjust_tail(ctx, tail_adj), 0, XDP_ABORTED);

    /* Reinitialize after length change. */
    pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

    /* Move and reverse Ethernet header before it gets overwritten by new IPv6
     * header.
     */
    if (base_layer == BASE_LAYER_L2) {
      struct ethhdr *old_eth = (void *)pkt.eth + (int)ADJ_LEN;
      assert_boundary(old_eth, pkt.end, XDP_ABORTED);
      eth_hdr_reverse(pkt.eth, old_eth);
    }

    assert_equal(exceed2go_exceeded(&pkt), true, XDP_ABORTED);
    break;
  case PKT_ECHO_REQUEST:
    count(COUNTER_PKT_ECHO_REQUEST);
    if (base_layer == BASE_LAYER_L2) {
      eth_hdr_reverse(pkt.eth, pkt.eth);
    }
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
    if (base_layer == BASE_LAYER_L2) {
      bpf_memcpy(&eth, pkt.eth, sizeof(struct ethhdr));
    }

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
    assert_equal(rc_head_adj, 0, TC_ACT_SHOT);

    /* Adjust packet length to match length requirements. */
    int new_len = ctx->len + pkt.tail_adjust;
    assert_equal(bpf_skb_change_tail(ctx, new_len, 0), 0, TC_ACT_SHOT);

    /* Reinitialize after length change. */
    pkt_info_set_ptrs(&pkt, ctx->data, ctx->data_end, base_layer);

    /* Restore and reverse Ethernet header. */
    if (base_layer == BASE_LAYER_L2) {
      assert_boundary(pkt.eth, pkt.end, TC_ACT_SHOT);
      eth_hdr_reverse(pkt.eth, &eth);
    }

    assert_equal(exceed2go_exceeded(&pkt), true, TC_ACT_SHOT);
    break;
  case PKT_ECHO_REQUEST:
    count(COUNTER_PKT_ECHO_REQUEST);
    if (base_layer == BASE_LAYER_L2) {
      eth_hdr_reverse(pkt.eth, pkt.eth);
    }
    exceed2go_echo(&pkt);
    break;
  }

  count(COUNTER_DO_REDIRECT);

  return bpf_redirect(ctx->ifindex, 0);
}

SEC("xdp")
int
exceed2go_xdp_l2(struct xdp_md *ctx) {
  return exceed2go_xdp(ctx, BASE_LAYER_L2);
}

// L3 interfaces do not support XDP and L3 interfaces are not supported in
// generic mode. It always expects an ethernet header:
// https://github.com/torvalds/linux/blob/04b8076df2534f08bb4190f90a24e0f7f8930aca/net/core/dev.c#L4891

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
