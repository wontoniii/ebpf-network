#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENCE[] SEC("license") = "GPL";

SEC("action")
int tc_icmp_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_UNSPEC; // The packet is incomplete, do nothing (UNSPEC
                              // lets the default action be performed, it should
                              // be let le packet pass by default)
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC; // Not an IPv4 packet, let it pass

    // Check IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_UNSPEC; // The packet is incomplete, let it pass

    if (ip->protocol != IPPROTO_ICMP) {
        return TC_ACT_UNSPEC; // Let non-ICMP packets pass
    }

//    bpf_printk("ICMP packet found");

    // Check ICMP header
    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)icmp + sizeof(*icmp) > data_end) {
        return TC_ACT_OK; // Incomplete, let pass
    }

    bpf_printk("Dropping ping with source %d.%d.%d.%d and destination %d.%d.%d.%d\n",
            ip->saddr & 0xFF, (ip->saddr >> 8) & 0xFF,
            (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF,
            ip->daddr & 0xFF, (ip->daddr >> 8) & 0xFF,
            (ip->daddr >> 16) & 0xFF, (ip->daddr >> 24) & 0xFF
            );
    return TC_ACT_SHOT; // Block all ICMP packets
}
