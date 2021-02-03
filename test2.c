#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
 
 
#define ETHER_ADDR_LEN 6       /* MAC地址长度(字节) */
 
/*以太网头*/
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};
/*IP头*/ //假设没有选项字段，长度20字节
struct sniff_ip
{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src,ip_dst;
};
/*UDP报头*/
struct sniff_udp
{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
};
 
 
 
pcap_t *source_pcap_t=NULL;
pcap_dumper_t *des_pcap_dumper_t=NULL;
 
int exit_main()
{
	printf("exit_main() is called.\n");
	if( NULL!=source_pcap_t )
	{
		pcap_close(source_pcap_t);
	}
	if( NULL!=des_pcap_dumper_t )
	{
		pcap_dump_close(des_pcap_dumper_t);
	}
	exit(0);
}
 
 
int main(int argc, char *argv[])
{
 
	//打开要处理pcap文件
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap_t=pcap_open_offline("traffic.pcap", errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(des_pcap_dumper_t=pcap_dump_open(source_pcap_t,"./rescult.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		exit_main();		
	}
 
	//读取数据包
	struct pcap_pkthdr packet;
	const u_char *pktStr;
	while(1)
	{
		pktStr=pcap_next(source_pcap_t, &packet);
		if( NULL==pktStr )
		{
			printf("pcap_next() return NULL.\n");
			break;		
		}
		else
		{
			//ARP数据包,不写入生成pcap文件
			if( 0x0608==((struct sniff_ethernet*)(pktStr))->ether_type )  
			{}
			//IPv4数据包,选择性写入生成pcap文件			
			else if( 0x0008==((struct sniff_ethernet*)(pktStr))->ether_type )
			{
				if( 0x02==((struct sniff_ip*)(pktStr+14))->ip_p )
				{
					//IGMPv3数据包，不写入生成pcap文件
					continue;
				}
				else if( 0x11==((struct sniff_ip*)(pktStr+14))->ip_p )
				{
					//UDP数据包，选择性写入生成pcap文件
					if( 0x8900==((struct sniff_udp*)(pktStr+14+20))->udp_sport || 0x8a00==((struct sniff_udp*)(pktStr+14+20))->udp_sport ||
						0x3500==((struct sniff_udp*)(pktStr+14+20))->udp_sport || 0x3500==((struct sniff_udp*)(pktStr+14+20))->udp_dport ||
						0x6c07==((struct sniff_udp*)(pktStr+14+20))->udp_sport || 0x6c07==((struct sniff_udp*)(pktStr+14+20))->udp_dport ||
						0xeb14==((struct sniff_udp*)(pktStr+14+20))->udp_sport || 0xeb14==((struct sniff_udp*)(pktStr+14+20))->udp_dport )
					{
						//NBNS端口137、BROWSER端口138、
						//DNS端口53
						//SSDP端口1900
						//LLMNR端口5355
					}
					else
					{
						//UDP其他端口，写入生成pcap文件
						pcap_dump((u_char*)des_pcap_dumper_t, &packet, pktStr);
					}
				}
				else
				{
					//TCP、或者其他协议，写入生成pcap文件
					pcap_dump((u_char*)des_pcap_dumper_t, &packet, pktStr);
				}
			}
			//非ARP、非IPv4的其他协议数据包，写入生成pcap文件
			else
			{
				pcap_dump((u_char*)des_pcap_dumper_t, &packet, pktStr);	
			}
		}
	}
	
	pcap_dump_close(des_pcap_dumper_t);
	pcap_close(source_pcap_t);
	return 0;
}