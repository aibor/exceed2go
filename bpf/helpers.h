// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"

#define __always_inline inline __attribute__((always_inline))
#define __packed        __attribute__((packed))

#define likely(p)   __builtin_expect(!!(p), 1)
#define unlikely(p) __builtin_expect(!!(p), 0)

static __always_inline void
memcpy(void *dst, const void *src, int size) {
  while (size >= 8) {
    *(__u64 *)dst = *(__u64 *)src;
    dst += 8;
    src += 8;
    size -= 8;
  }

  if (size >= 4) {
    *(__u32 *)dst = *(__u32 *)src;
    dst += 4;
    src += 4;
    size -= 4;
  }

  if (size >= 2) {
    *(__u16 *)dst = *(__u16 *)src;
    dst += 2;
    src += 2;
    size -= 2;
  }

  if (size == 1) {
    *(__u8 *)dst = *(__u8 *)src;
  }
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
