  // gcc test.c -lpcap -o test

  #include<stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <pcap.h>
  #include <time.h>
  #include <arpa/inet.h>


  #define PCAP_FILE "traffic.pcap"
  #define ETHER_ADDR_LEN 6

  struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* 目的主机的地址 */

    u_char ether_shost[ETHER_ADDR_LEN]; /* 源主机的地址 */

    u_short ether_type; /* IP? ARP? RARP? etc */
  };

  struct sniff_ip {
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int ip_hl:4, /* 头部长度 */
    ip_v:4; /* 版本号 */
    #if BYTE_ORDER == BIG_ENDIAN
    u_int ip_v:4, /* 版本号 */
    ip_hl:4; /* 头部长度 */
    #endif
    #endif /* not _IP_VHL */
    u_char ip_tos; /* 服务的类型 */
    u_short ip_len; /* 总长度 */
    u_short ip_id; /*包标志号 */
    u_short ip_off; /* 碎片偏移 */
    #define IP_RF 0x8000 /* 保留的碎片标志 */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* 多碎片标志*/
    #define IP_OFFMASK 0x1fff /*分段位 */
    u_char ip_ttl; /* 数据包的生存时间 */
    u_char ip_p; /* 所使用的协议 */
    u_short ip_sum; /* 校验和 */
    struct in_addr ip_src,ip_dst; /* 源地址、目的地址*/
  };

  struct sniff_tcp {
    u_short th_sport; /* 源端口 */
    u_short th_dport; /* 目的端口 */
    int th_seq; /* 包序号tcp_seq */
    int th_ack; /* 确认序号tcp_seq */
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4, /* 还没有用到 */
    th_off:4; /* 数据偏移 */
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
    u_int th_off:4, /* 数据偏移*/
    th_x2:4; /*还没有用到 */
    #endif
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FINTH_SYNTH_RSTTH_ACKTH_URGTH_ECETH_CWR)
    u_short th_win; /* TCP滑动窗口 */
    u_short th_sum; /* 头部校验和 */
    u_short th_urp; /* 紧急服务位 */
  };

  int main()
  {
    char ebuf[PCAP_ERRBUF_SIZE];
    FILE *fp = fopen(PCAP_FILE, "rb");
    pcap_t *handle;
    handle = pcap_open_offline(PCAP_FILE,ebuf);
    struct bpf_program filter;
    bpf_u_int32 net; 
    pcap_compile(handle, &filter, "port 80", 0, net);
    struct pcap_pkthdr header;
    const u_char *packet;

    packet = pcap_next(handle, &header);
    int i=0;
    //printf("Jacked a packet with length of [%d]\n", header.len);
    while (packet = pcap_next(handle, &header))
    {
      //printf("Jacked a packet with length of [%d]\n", header.len);
      const struct sniff_ethernet *ethernet; /* 以太网帧头部*/
      const struct sniff_ip *ip; /* IP包头部 */
      const struct sniff_tcp *tcp; /* TCP包头部 */
      const char *payload; /* 数据包的有效载荷*/
      /*为了让它的可读性好，我们计算每个结构体中的变量大小*/
      int size_ethernet = sizeof(struct sniff_ethernet);
      int size_ip = sizeof(struct sniff_ip);
      int size_tcp = sizeof(struct sniff_tcp);
      ethernet = (struct sniff_ethernet*)(packet);
      ip = (struct sniff_ip*)(packet + size_ethernet);
      // tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);
      // payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);

        // protocol type
        printf("%d\n", ethernet->ether_type);
        // src ip address and dst ip address
        printf("%s %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
        // src port and dst port
        // printf("%d %d\n", tcp->th_sport, tcp->th_dport);
      
      i++;
    }
    printf("\n%d\n",i);
    // const struct sniff_ethernet *ethernet; /* 以太网帧头部*/

    // const struct sniff_ip *ip; /* IP包头部 */

    // const struct sniff_tcp *tcp; /* TCP包头部 */

    // const char *payload; /* 数据包的有效载荷*/

    // /*为了让它的可读性好，我们计算每个结构体中的变量大小*/

    // int size_ethernet = sizeof(struct sniff_ethernet);

    // int size_ip = sizeof(struct sniff_ip);

    // int size_tcp = sizeof(struct sniff_tcp);

    // ethernet = (struct sniff_ethernet*)(packet);

    // ip = (struct sniff_ip*)(packet + size_ethernet);

    // tcp = (struct sniff_tcp*)(packet + size_ethernet + size_ip);

    // payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);

    // // protocol type
    // printf("%d\n", ethernet->ether_type);
    // // src ip address and dst ip address
    // printf("%s %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
    // // src port and dst port
    // printf("%d %d\n", tcp->th_sport, tcp->th_dport);
    return 0;
  }