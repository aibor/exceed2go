// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"

#define __always_inline inline __attribute__((always_inline))
#define __packed        __attribute__((packed))

#define likely(p)   __builtin_expect(!!(p), 1)
#define unlikely(p) __builtin_expect(!!(p), 0)
#define memcpy      __builtin_memcpy

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
