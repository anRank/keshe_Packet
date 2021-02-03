#include<stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>


#define PCAP_FILE "traffic.pcap"
#define ETHER_ADDR_LEN 6

typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;

typedef struct ip_hdr
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;

int main()
{
    char ebuf[PCAP_ERRBUF_SIZE];
    FILE *fp = fopen(PCAP_FILE, "rb");
    pcap_t *handle;
    handle = pcap_open_offline(PCAP_FILE,ebuf);
    struct pcap_pkthdr header;
    const u_char *packet;
    
    u_int eth_len=sizeof(struct eth_hdr);
    u_int ip_len=sizeof(struct ip_hdr);
    u_int tcp_len=sizeof(struct tcp_hdr);
    u_int udp_len=sizeof(struct udp_hdr);
    int i=0;
    while (packet = pcap_next(handle, &header))
    {
        eth_hdr *ethernet =(eth_hdr *)packet;

        if(ntohs(ethernet->eth_type)==0x0800)   // IPV4 
        {
            ip_hdr *ip=(ip_hdr*)(packet+eth_len);
            if(ip->protocol==6){
                printf("tcp  ");
                printf("source ip : %d.%d.%d.%d  ",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
                printf("dest ip : %d.%d.%d.%d  ",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
                tcp_hdr* tcp=(tcp_hdr*)(packet+eth_len+ip_len);
                printf("tcp source port : %u  ",tcp->sport);
                printf("tcp dest port : %u\n",tcp->dport);
            }else if(ip->protocol==17){
                printf("udp ");
                printf("source ip : %d.%d.%d.%d  ",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
                printf("dest ip : %d.%d.%d.%d  ",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
                udp_hdr *udp=(udp_hdr*)(packet+eth_len+ip_len);
                printf("udp source port : %u  ",udp->sport);
                printf("udp dest port : %u  \n",udp->dport);
            }else {
                // printf("other transport protocol is used\n");
                continue;
            }   
        }else
        {

            // printf("2");
        }
        i++;
        if(i==30){
            return 0;
        }
    }
    
    
    

    return 0;
}