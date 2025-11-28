// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include "types.h"
#include "helpers.h"
#include "libbpf/bpf_helpers.h"

#define next_header(h) ((void *)(h + 1))

#define assert_boundary(h, end, ret) \
  if (unlikely(next_header(h) > end)) \
  return ret

#define assert_equal(f, e, ret) \
  if (unlikely(f != e)) \
  return ret

/* Calculate checksum of the data starting with the given sum. If max4 is true,
 * only full 4 byte blocks are summed up. Trailing bytes are left out.
 * The packet must not be longer than 2044 byte.
 */
static __always_inline __wsum
pkt_csum(const void *data, const void *data_end, const bool max4, __wsum sum) {
  /* Sum up all paket data. Walk in biggest possible chunks
   * Since 1024 (2^10, 1 << 9) is the biggest chunk we can process based on the
   * exponent decrement with the bpf_csum_diff size limitation, the maximum
   * packet size supported is 2044.
   */
  for (__u8 exp = 9; exp >= 2; exp--) {
    /* Cap at 512 because bpf_csum_diff can take max 512 byte. */
    __u16 chunk_size = 1 << (exp > 8 ? 8 : exp);
    if (data + chunk_size > data_end) {
      continue;
    }

    sum = bpf_csum_diff(NULL, 0, (void *)data, chunk_size, sum);
    data += chunk_size;
  }

  if (max4) {
    return sum;
  }

  __u32 addend     = 0;
  void *addend_ptr = &addend;
  if (data + 2 <= data_end) {
    *(__u16 *)addend_ptr++ = *(__be16 *)data++;
  }
  if (data + 1 <= data_end) {
    *(__u8 *)addend_ptr += *(__u8 *)data++;
  }
  sum = bpf_csum_diff(NULL, 0, &addend, 4, sum);

  return sum;
}
