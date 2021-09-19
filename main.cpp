#include <stdio.h>
#include <iso646.h>
#include <algorithm>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
using namespace std;

bool parse(int argc, char *argv[])
{
    if (not(argc == 2))
    {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test eth0\n");
        return false;
    }
    else
        return true;
}
bool get_pcd(pcap_t **pcap, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (*pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return false;
    }
    else
        return true;
}

int main(int argc, char *argv[])
{
    //argument check
    if (not parse(argc, argv))
        return -1;

    //packet capture descripter
    pcap_t *pcap = NULL;
    if (not get_pcd(&pcap, argv[1]))
        return -1;

    //get packet
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        //didn't get packet
        if (res == 0)
            continue;
        //can't get packet anymore
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //success getting packet

        //Ethernet Header
        struct ether_header *Ethernet = (struct ether_header *)packet;
        //IP Header
        if (not(ntohs(Ethernet->ether_type) == ETHERTYPE_IP))
            continue;
        struct ip *ipv4 = (struct ip *)(packet + sizeof(struct ether_header));
        //TCP Header
        if (not(ipv4->ip_p == IPPROTO_TCP))
            continue;
        struct tcphdr *TCP = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipv4->ip_hl * 4);
        //payload
        int header_len = sizeof(struct ether_header) + ipv4->ip_hl * 4 + TCP->th_off * 4;
        int payload_len = header->caplen - header_len;
        if (payload_len > 8)
            payload_len = 8;
        const char *payload = (const char *)(packet + header_len);

        printf("Ethernet - source mac addr: %s\n", ether_ntoa((const ether_addr *)Ethernet->ether_shost));
        printf("Ethernet - destination mac addr: %s\n", ether_ntoa((const ether_addr *)Ethernet->ether_dhost));
        printf("IP - source IP addr: %s\n", inet_ntoa(ipv4->ip_src));
        printf("IP - destination IP addr: %s\n", inet_ntoa(ipv4->ip_dst));
        printf("TCP - source port: %d\n", ntohs(TCP->th_sport));
        printf("TCP - destination port: %d\n", ntohs(TCP->th_dport));
        for (int i = 0; i < payload_len; i++)
            printf("%X ", payload[i]);
        printf("\n\n");
    }
    //close
    pcap_close(pcap);
    return 0;
}
