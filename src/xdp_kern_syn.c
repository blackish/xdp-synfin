/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") xdp_stats_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(__u64),
        .max_entries = 3,
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)     ((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{
  __u32 key = 0;
  __u64 *rec;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if ( data+1 > data_end )
    return XDP_ABORTED;

  void *hdr = data;
        struct ethhdr *eth = hdr;
  int ethhdrlen = sizeof(*eth);
  if ( hdr + 1 > data_end )
          return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;
  if ( hdr + ethhdrlen + 11 > data_end )
          return XDP_PASS;
  struct iphdr *ip = hdr + ethhdrlen;
  if ( ip->protocol != 6 )
    return XDP_PASS;
  if (  hdr + ethhdrlen + ip->ihl * 4 + 21 > data_end )
          return XDP_PASS;

  struct tcphdr *tcp = hdr + ethhdrlen + ip->ihl * 4;
  if ( tcp->syn == 1 ) {
    key = 0;
    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
      return XDP_ABORTED;
    lock_xadd(rec, 1);
    return XDP_PASS;
  }
  if ( tcp->fin == 1 ) {
    key = 1;
    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
      return XDP_ABORTED;
    lock_xadd(rec, 1);
    return XDP_PASS;
  }
        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

