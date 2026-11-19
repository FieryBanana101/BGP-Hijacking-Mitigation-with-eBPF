#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

/*
 * BGP Hijacking Mitigation Template (XDP)
 * Placeholders are dynamically injected by runner.py based on LLM reasoning:
 *   __TARGET_NET__: Network address in network byte order (__builtin_bswap32)
 *   __TARGET_MASK__: Subnet mask in network byte order (__builtin_bswap32)
 *   __FILTER_MODE__: 1 = Match Destination Prefix (hijacked IP space), 2 = Match Source IP (rogue origin)
 */
#define TARGET_NET  __TARGET_NET__
#define TARGET_MASK __TARGET_MASK__
#define FILTER_MODE __FILTER_MODE__

SEC("xdp")
int xdp_drop_hijack(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Filter only IPv4 traffic */
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /*
     * Mode 1 (Default): Destination Prefix Mitigation
     * Protects hijacked address space. If incoming traffic is directed to the
     * hijacked prefix announced by a rogue AS, drop it at line rate to prevent
     * interception, blackholing, or traffic redirection.
     */
    if (FILTER_MODE == 1) {
        if ((ip->daddr & TARGET_MASK) == TARGET_NET) {
            return XDP_DROP;
        }
    }

    /*
     * Mode 2: Source Prefix / Peer Mitigation
     * Drops traffic originating from the rogue AS or malicious host.
     */
    if (FILTER_MODE == 2) {
        if ((ip->saddr & TARGET_MASK) == TARGET_NET) {
            return XDP_DROP;
        }
    }

    /*
     * Mode 3: Bidirectional match
     */
    if (FILTER_MODE == 3) {
        if (((ip->daddr & TARGET_MASK) == TARGET_NET) ||
            ((ip->saddr & TARGET_MASK) == TARGET_NET)) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
