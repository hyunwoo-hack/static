#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <cctype>

#define SNAP_LEN 1518
#define MSG_LEN 32

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4);
    
    std::cout << "Ethernet Header: Src MAC: " << ether_ntoa((struct ether_addr *)eth->ether_shost)
              << ", Dst MAC: " << ether_ntoa((struct ether_addr *)eth->ether_dhost) << std::endl;
    std::cout << "IP Header: Src IP: " << inet_ntoa(ip_hdr->ip_src)
              << ", Dst IP: " << inet_ntoa(ip_hdr->ip_dst) << std::endl;
    std::cout << "TCP Header: Src Port: " << ntohs(tcp_hdr->th_sport)
              << ", Dst Port: " << ntohs(tcp_hdr->th_dport) << std::endl;
    
    const u_char *payload = (u_char *)(packet + sizeof(struct ether_header) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
    int payload_length = header->caplen - (payload - packet);
    if (payload_length > 0) {
        std::cout << "Message: ";
        for (int i = 0; i < MSG_LEN && i < payload_length; i++) {
            std::cout << (std::isprint(payload[i]) ? (char)payload[i] : '.');
        }
        std::cout << std::endl;
    }
    std::cout << "--------------------------------------------------------" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("enp0s1", SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return 1;
    }
    
    struct bpf_program filter;
    pcap_compile(handle, &filter, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &filter);
    
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    return 0;
}
