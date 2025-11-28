// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"
#include "helpers.h"
#include "libbpf/bpf_helpers.h"

#define ETH_HLEN   sizeof(struct ethhdr)
#define ETH_ALEN   6
#define ETH_P_IPV6 0x86DD

struct mac_addr {
  __u8 addr[ETH_ALEN];
} __packed;

struct ethhdr {
  struct mac_addr daddr;
  struct mac_addr saddr;
  __be16          proto;
} __packed;

/* Swap ethernet addresses. new and old may point to the same header. */
static __always_inline void
eth_hdr_reverse(struct ethhdr *new, struct ethhdr *old) {
  struct mac_addr tmp;
  memcpy(&tmp, &old->daddr, ETH_ALEN);
  memcpy(&new->daddr, &old->saddr, ETH_ALEN);
  memcpy(&new->saddr, &tmp, ETH_ALEN);
  new->proto = old->proto;
}
