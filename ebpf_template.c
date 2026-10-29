#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define TARGET_IP __TARGET_IP__ // Akan dilengkapi oleh LLM lokal

SEC("xdp")
int xdp_drop_hijack(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end) return XDP_PASS;
    
    // Cek IPv4
    if(eth->h_proto != __builtin_bswap16(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if((void *)(ip + 1) > data_end) return XDP_PASS;

    // Drop test untuk hardcoded malicious IP yang diberikan oleh LLM
    if(ip->saddr == TARGET_IP) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";