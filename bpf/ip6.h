// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"
#include "helpers.h"
#include "libbpf/bpf_helpers.h"

#define IPV6_MTU_MIN   1280
#define IPV6_ALEN      16
#define IPV6_HOP_LIMIT 64
#define IPPROTO_ICMPV6 58

struct in6_addr {
  union {
    __u8   u6_addr8[IPV6_ALEN];
    __be16 u6_addr16[IPV6_ALEN / 2];
    __be32 u6_addr32[IPV6_ALEN / 4];
    __be64 u6_addr64[IPV6_ALEN / 8];
  } in6_u;
};

struct ipv6hdr {
  __u8            priority : 4;
  __u8            version  : 4;
  __u8            flow_lbl[3];
  __be16          payload_len;
  __u8            nexthdr;
  __u8            hop_limit;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

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
ipv6_init(struct ipv6hdr        *ipv6,
          const __be16           payload_len,
          __u8                   nexthdr,
          const struct in6_addr *saddr,
          const struct in6_addr *daddr) {
  ipv6->version     = 6;
  ipv6->priority    = 0;
  ipv6->flow_lbl[0] = 0;
  ipv6->flow_lbl[1] = 0;
  ipv6->flow_lbl[2] = 0;
  ipv6->payload_len = payload_len;
  ipv6->nexthdr     = nexthdr;
  ipv6->hop_limit   = IPV6_HOP_LIMIT;

  in6_addr_copy(&ipv6->saddr, saddr);
  in6_addr_copy(&ipv6->daddr, daddr);
}

/* Calculate IPv6 pseudo header checksum with given initial value. */
static __always_inline __wsum
ipv6_pseudo_hdr_csum(const struct ipv6hdr *ipv6, __wsum sum) {
  /* Payload_len is already in network byte order. */
  sum = csum_add(sum, ((__u32)ipv6->payload_len) << 16);
  sum = csum_add(sum, ((__u32)ipv6->nexthdr) << 24);
  sum = bpf_csum_diff(NULL, 0, (void *)&ipv6->saddr, 2 * IPV6_ALEN, sum);

  return sum;
}
