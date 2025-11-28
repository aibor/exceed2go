// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"

#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_ECHO_REQUEST  128
#define ICMP6_ECHO_REPLY    129

struct icmpv6_echo {
  __be16 identifier;
  __be16 sequence;
};

struct icmp6hdr {
  __u8    icmp6_type;
  __u8    icmp6_code;
  __sum16 icmp6_cksum;
  union {
    __be32             un_data32[1];
    __be16             un_data16[2];
    __u8               un_data8[4];
    struct icmpv6_echo u_echo;
  } icmp6_dataun;
};
