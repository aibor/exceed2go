// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#define NULL ((void *)0)

typedef _Bool bool;

enum {
  false = 0,
  true  = 1,
};

typedef signed char      __s8;
typedef short signed int __s16;
typedef int              __s32;
typedef long long int    __s64;

typedef unsigned char          __u8;
typedef short unsigned int     __u16;
typedef unsigned int           __u32;
typedef long long unsigned int __u64;

typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};

struct __sk_buff {
  __u32 len;
  __u32 pkt_type;
  __u32 mark;
  __u32 queue_mapping;
  __u32 protocol;
  __u32 vlan_present;
  __u32 vlan_tci;
  __u32 vlan_proto;
  __u32 priority;
  __u32 ingress_ifindex;
  __u32 ifindex;
  __u32 tc_index;
  __u32 cb[5];
  __u32 hash;
  __u32 tc_classid;
  __u32 data;
  __u32 data_end;
  __u32 napi_id;
  __u32 family;
  __u32 remote_ip4;
  __u32 local_ip4;
  __u32 remote_ip6[4];
  __u32 local_ip6[4];
  __u32 remote_port;
  __u32 local_port;
  __u32 data_meta;
  union {
    struct bpf_flow_keys *flow_keys;
  };
  __u64 tstamp;
  __u32 wire_len;
  __u32 gso_segs;
  union {
    struct bpf_sock *sk;
  };
  __u32 gso_size;
  __u8  tstamp_type;
  __u64 hwtstamp;
};

struct bpf_iter_num {
  __u64 __opaque[1];
};

enum xdp_action {
  XDP_ABORTED  = 0,
  XDP_DROP     = 1,
  XDP_PASS     = 2,
  XDP_TX       = 3,
  XDP_REDIRECT = 4,
};

enum tc_action {
  TC_ACT_UNSPEC   = -1,
  TC_ACT_OK       = 0,
  TC_ACT_SHOT     = 2,
  TC_ACT_REDIRECT = 7,
};

enum bpf_adj_room_mode {
  BPF_ADJ_ROOM_NET,
  BPF_ADJ_ROOM_MAC,
};

enum {
  BPF_F_ADJ_ROOM_FIXED_GSO     = (1ULL << 0),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = (1ULL << 1),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = (1ULL << 2),
  BPF_F_ADJ_ROOM_ENCAP_L4_GRE  = (1ULL << 3),
  BPF_F_ADJ_ROOM_ENCAP_L4_UDP  = (1ULL << 4),
  BPF_F_ADJ_ROOM_NO_CSUM_RESET = (1ULL << 5),
  BPF_F_ADJ_ROOM_ENCAP_L2_ETH  = (1ULL << 6),
  BPF_F_ADJ_ROOM_DECAP_L3_IPV4 = (1ULL << 7),
  BPF_F_ADJ_ROOM_DECAP_L3_IPV6 = (1ULL << 8),
};

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC                = 0,
  BPF_MAP_TYPE_HASH                  = 1,
  BPF_MAP_TYPE_ARRAY                 = 2,
  BPF_MAP_TYPE_PROG_ARRAY            = 3,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
  BPF_MAP_TYPE_PERCPU_HASH           = 5,
  BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
  BPF_MAP_TYPE_STACK_TRACE           = 7,
  BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
  BPF_MAP_TYPE_LRU_HASH              = 9,
  BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
  BPF_MAP_TYPE_LPM_TRIE              = 11,
  BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
  BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
  BPF_MAP_TYPE_DEVMAP                = 14,
  BPF_MAP_TYPE_SOCKMAP               = 15,
  BPF_MAP_TYPE_CPUMAP                = 16,
  BPF_MAP_TYPE_XSKMAP                = 17,
  BPF_MAP_TYPE_SOCKHASH              = 18,
  BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
  BPF_MAP_TYPE_QUEUE                 = 22,
  BPF_MAP_TYPE_STACK                 = 23,
  BPF_MAP_TYPE_SK_STORAGE            = 24,
  BPF_MAP_TYPE_DEVMAP_HASH           = 25,
  BPF_MAP_TYPE_STRUCT_OPS            = 26,
  BPF_MAP_TYPE_RINGBUF               = 27,
  BPF_MAP_TYPE_INODE_STORAGE         = 28,
  BPF_MAP_TYPE_TASK_STORAGE          = 29,
  BPF_MAP_TYPE_BLOOM_FILTER          = 30,
};

enum bpf_func_id {
  BPF_FUNC_unspec                         = 0,
  BPF_FUNC_map_lookup_elem                = 1,
  BPF_FUNC_map_update_elem                = 2,
  BPF_FUNC_map_delete_elem                = 3,
  BPF_FUNC_probe_read                     = 4,
  BPF_FUNC_ktime_get_ns                   = 5,
  BPF_FUNC_trace_printk                   = 6,
  BPF_FUNC_get_prandom_u32                = 7,
  BPF_FUNC_get_smp_processor_id           = 8,
  BPF_FUNC_skb_store_bytes                = 9,
  BPF_FUNC_l3_csum_replace                = 10,
  BPF_FUNC_l4_csum_replace                = 11,
  BPF_FUNC_tail_call                      = 12,
  BPF_FUNC_clone_redirect                 = 13,
  BPF_FUNC_get_current_pid_tgid           = 14,
  BPF_FUNC_get_current_uid_gid            = 15,
  BPF_FUNC_get_current_comm               = 16,
  BPF_FUNC_get_cgroup_classid             = 17,
  BPF_FUNC_skb_vlan_push                  = 18,
  BPF_FUNC_skb_vlan_pop                   = 19,
  BPF_FUNC_skb_get_tunnel_key             = 20,
  BPF_FUNC_skb_set_tunnel_key             = 21,
  BPF_FUNC_perf_event_read                = 22,
  BPF_FUNC_redirect                       = 23,
  BPF_FUNC_get_route_realm                = 24,
  BPF_FUNC_perf_event_output              = 25,
  BPF_FUNC_skb_load_bytes                 = 26,
  BPF_FUNC_get_stackid                    = 27,
  BPF_FUNC_csum_diff                      = 28,
  BPF_FUNC_skb_get_tunnel_opt             = 29,
  BPF_FUNC_skb_set_tunnel_opt             = 30,
  BPF_FUNC_skb_change_proto               = 31,
  BPF_FUNC_skb_change_type                = 32,
  BPF_FUNC_skb_under_cgroup               = 33,
  BPF_FUNC_get_hash_recalc                = 34,
  BPF_FUNC_get_current_task               = 35,
  BPF_FUNC_probe_write_user               = 36,
  BPF_FUNC_current_task_under_cgroup      = 37,
  BPF_FUNC_skb_change_tail                = 38,
  BPF_FUNC_skb_pull_data                  = 39,
  BPF_FUNC_csum_update                    = 40,
  BPF_FUNC_set_hash_invalid               = 41,
  BPF_FUNC_get_numa_node_id               = 42,
  BPF_FUNC_skb_change_head                = 43,
  BPF_FUNC_xdp_adjust_head                = 44,
  BPF_FUNC_probe_read_str                 = 45,
  BPF_FUNC_get_socket_cookie              = 46,
  BPF_FUNC_get_socket_uid                 = 47,
  BPF_FUNC_set_hash                       = 48,
  BPF_FUNC_setsockopt                     = 49,
  BPF_FUNC_skb_adjust_room                = 50,
  BPF_FUNC_redirect_map                   = 51,
  BPF_FUNC_sk_redirect_map                = 52,
  BPF_FUNC_sock_map_update                = 53,
  BPF_FUNC_xdp_adjust_meta                = 54,
  BPF_FUNC_perf_event_read_value          = 55,
  BPF_FUNC_perf_prog_read_value           = 56,
  BPF_FUNC_getsockopt                     = 57,
  BPF_FUNC_override_return                = 58,
  BPF_FUNC_sock_ops_cb_flags_set          = 59,
  BPF_FUNC_msg_redirect_map               = 60,
  BPF_FUNC_msg_apply_bytes                = 61,
  BPF_FUNC_msg_cork_bytes                 = 62,
  BPF_FUNC_msg_pull_data                  = 63,
  BPF_FUNC_bind                           = 64,
  BPF_FUNC_xdp_adjust_tail                = 65,
  BPF_FUNC_skb_get_xfrm_state             = 66,
  BPF_FUNC_get_stack                      = 67,
  BPF_FUNC_skb_load_bytes_relative        = 68,
  BPF_FUNC_fib_lookup                     = 69,
  BPF_FUNC_sock_hash_update               = 70,
  BPF_FUNC_msg_redirect_hash              = 71,
  BPF_FUNC_sk_redirect_hash               = 72,
  BPF_FUNC_lwt_push_encap                 = 73,
  BPF_FUNC_lwt_seg6_store_bytes           = 74,
  BPF_FUNC_lwt_seg6_adjust_srh            = 75,
  BPF_FUNC_lwt_seg6_action                = 76,
  BPF_FUNC_rc_repeat                      = 77,
  BPF_FUNC_rc_keydown                     = 78,
  BPF_FUNC_skb_cgroup_id                  = 79,
  BPF_FUNC_get_current_cgroup_id          = 80,
  BPF_FUNC_get_local_storage              = 81,
  BPF_FUNC_sk_select_reuseport            = 82,
  BPF_FUNC_skb_ancestor_cgroup_id         = 83,
  BPF_FUNC_sk_lookup_tcp                  = 84,
  BPF_FUNC_sk_lookup_udp                  = 85,
  BPF_FUNC_sk_release                     = 86,
  BPF_FUNC_map_push_elem                  = 87,
  BPF_FUNC_map_pop_elem                   = 88,
  BPF_FUNC_map_peek_elem                  = 89,
  BPF_FUNC_msg_push_data                  = 90,
  BPF_FUNC_msg_pop_data                   = 91,
  BPF_FUNC_rc_pointer_rel                 = 92,
  BPF_FUNC_spin_lock                      = 93,
  BPF_FUNC_spin_unlock                    = 94,
  BPF_FUNC_sk_fullsock                    = 95,
  BPF_FUNC_tcp_sock                       = 96,
  BPF_FUNC_skb_ecn_set_ce                 = 97,
  BPF_FUNC_get_listener_sock              = 98,
  BPF_FUNC_skc_lookup_tcp                 = 99,
  BPF_FUNC_tcp_check_syncookie            = 100,
  BPF_FUNC_sysctl_get_name                = 101,
  BPF_FUNC_sysctl_get_current_value       = 102,
  BPF_FUNC_sysctl_get_new_value           = 103,
  BPF_FUNC_sysctl_set_new_value           = 104,
  BPF_FUNC_strtol                         = 105,
  BPF_FUNC_strtoul                        = 106,
  BPF_FUNC_sk_storage_get                 = 107,
  BPF_FUNC_sk_storage_delete              = 108,
  BPF_FUNC_send_signal                    = 109,
  BPF_FUNC_tcp_gen_syncookie              = 110,
  BPF_FUNC_skb_output                     = 111,
  BPF_FUNC_probe_read_user                = 112,
  BPF_FUNC_probe_read_kernel              = 113,
  BPF_FUNC_probe_read_user_str            = 114,
  BPF_FUNC_probe_read_kernel_str          = 115,
  BPF_FUNC_tcp_send_ack                   = 116,
  BPF_FUNC_send_signal_thread             = 117,
  BPF_FUNC_jiffies64                      = 118,
  BPF_FUNC_read_branch_records            = 119,
  BPF_FUNC_get_ns_current_pid_tgid        = 120,
  BPF_FUNC_xdp_output                     = 121,
  BPF_FUNC_get_netns_cookie               = 122,
  BPF_FUNC_get_current_ancestor_cgroup_id = 123,
  BPF_FUNC_sk_assign                      = 124,
  BPF_FUNC_ktime_get_boot_ns              = 125,
  BPF_FUNC_seq_printf                     = 126,
  BPF_FUNC_seq_write                      = 127,
  BPF_FUNC_sk_cgroup_id                   = 128,
  BPF_FUNC_sk_ancestor_cgroup_id          = 129,
  BPF_FUNC_ringbuf_output                 = 130,
  BPF_FUNC_ringbuf_reserve                = 131,
  BPF_FUNC_ringbuf_submit                 = 132,
  BPF_FUNC_ringbuf_discard                = 133,
  BPF_FUNC_ringbuf_query                  = 134,
  BPF_FUNC_csum_level                     = 135,
  BPF_FUNC_skc_to_tcp6_sock               = 136,
  BPF_FUNC_skc_to_tcp_sock                = 137,
  BPF_FUNC_skc_to_tcp_timewait_sock       = 138,
  BPF_FUNC_skc_to_tcp_request_sock        = 139,
  BPF_FUNC_skc_to_udp6_sock               = 140,
  BPF_FUNC_get_task_stack                 = 141,
  BPF_FUNC_load_hdr_opt                   = 142,
  BPF_FUNC_store_hdr_opt                  = 143,
  BPF_FUNC_reserve_hdr_opt                = 144,
  BPF_FUNC_inode_storage_get              = 145,
  BPF_FUNC_inode_storage_delete           = 146,
  BPF_FUNC_d_path                         = 147,
  BPF_FUNC_copy_from_user                 = 148,
  BPF_FUNC_snprintf_btf                   = 149,
  BPF_FUNC_seq_printf_btf                 = 150,
  BPF_FUNC_skb_cgroup_classid             = 151,
  BPF_FUNC_redirect_neigh                 = 152,
  BPF_FUNC_per_cpu_ptr                    = 153,
  BPF_FUNC_this_cpu_ptr                   = 154,
  BPF_FUNC_redirect_peer                  = 155,
  BPF_FUNC_task_storage_get               = 156,
  BPF_FUNC_task_storage_delete            = 157,
  BPF_FUNC_get_current_task_btf           = 158,
  BPF_FUNC_bprm_opts_set                  = 159,
  BPF_FUNC_ktime_get_coarse_ns            = 160,
  BPF_FUNC_ima_inode_hash                 = 161,
  BPF_FUNC_sock_from_file                 = 162,
  BPF_FUNC_check_mtu                      = 163,
  BPF_FUNC_for_each_map_elem              = 164,
  BPF_FUNC_snprintf                       = 165,
  BPF_FUNC_sys_bpf                        = 166,
  BPF_FUNC_btf_find_by_name_kind          = 167,
  BPF_FUNC_sys_close                      = 168,
  BPF_FUNC_timer_init                     = 169,
  BPF_FUNC_timer_set_callback             = 170,
  BPF_FUNC_timer_start                    = 171,
  BPF_FUNC_timer_cancel                   = 172,
  BPF_FUNC_get_func_ip                    = 173,
  BPF_FUNC_get_attach_cookie              = 174,
  BPF_FUNC_task_pt_regs                   = 175,
  BPF_FUNC_get_branch_snapshot            = 176,
  BPF_FUNC_trace_vprintk                  = 177,
  BPF_FUNC_skc_to_unix_sock               = 178,
  BPF_FUNC_kallsyms_lookup_name           = 179,
  BPF_FUNC_find_vma                       = 180,
  BPF_FUNC_loop                           = 181,
  BPF_FUNC_strncmp                        = 182,
  BPF_FUNC_get_func_arg                   = 183,
  BPF_FUNC_get_func_ret                   = 184,
  BPF_FUNC_get_func_arg_cnt               = 185,
  BPF_FUNC_get_retval                     = 186,
  BPF_FUNC_set_retval                     = 187,
  BPF_FUNC_xdp_get_buff_len               = 188,
  BPF_FUNC_xdp_load_bytes                 = 189,
  BPF_FUNC_xdp_store_bytes                = 190,
  BPF_FUNC_copy_from_user_task            = 191,
  BPF_FUNC_skb_set_tstamp                 = 192,
  BPF_FUNC_ima_file_hash                  = 193,
  BPF_FUNC_kptr_xchg                      = 194,
  BPF_FUNC_map_lookup_percpu_elem         = 195,
  BPF_FUNC_skc_to_mptcp_sock              = 196,
  BPF_FUNC_dynptr_from_mem                = 197,
  BPF_FUNC_ringbuf_reserve_dynptr         = 198,
  BPF_FUNC_ringbuf_submit_dynptr          = 199,
  BPF_FUNC_ringbuf_discard_dynptr         = 200,
  BPF_FUNC_dynptr_read                    = 201,
  BPF_FUNC_dynptr_write                   = 202,
  BPF_FUNC_dynptr_data                    = 203,
  __BPF_FUNC_MAX_ID                       = 204,
};
