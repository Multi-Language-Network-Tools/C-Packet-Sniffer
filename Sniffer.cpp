#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

using namespace std;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header;
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        cout << "Packet captured: "
             << inet_ntoa(ip_header->ip_src) << " -> "
             << inet_ntoa(ip_header->ip_dst)
             << " | Protocol: " << (int) ip_header->ip_p
             << " | Length: " << ntohs(ip_header->ip_len)
             << endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Change "eth0" to your network interface
    char dev[] = "eth0";

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Could not open device: " << errbuf << endl;
        return 1;
    }

    cout << "Sniffer started on interface " << dev << endl;

    pcap_loop(handle, 10, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
