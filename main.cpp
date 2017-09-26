#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

////////////////////////////////////////////////////
//캡쳐하고 싶은 패킷 개수를 여기 설정
#define RPT 10
////////////////////////////////////////////////////


#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct libnet_ethernet_hdr {
	u_int8_t ether_dhost[ETHER_ADDR_LEN];	//destination ethernet addr
	u_int8_t ether_shost[ETHER_ADDR_LEN];	//source ethernet addr
	u_int16_t ether_type;				//protocol
};

struct libnet_ipv4_hdr {
//#if (LIBNET_LIL_ENDIAN)
//  u_int8_t ip_hl:4,      /* header length */
//         ip_v:4;         /* version */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t ip_v:4,       /* version */
//         ip_hl:4;        /* header length */
//#endif
	u_int8_t ip_vhl;	
	u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
//#if (LIBNET_LIL_ENDIAN)
//  u_int8_t th_x2:4,         /* (unused) */
//           th_off:4;        /* data offset */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t th_off:4,        /* data offset */
//           th_x2:4;         /* (unused) */
//#endif
	u_int8_t th_offx2;
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

int main() {
/*
  if (argc != 2) {
    usage();
    return -1;
  }
*/	
	const char* name = "류현서";
	printf("\n[sub26_2017]pcap_test[%s]\n", name);

	pcap_t* handle;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0, j, rpt_count;
	char errbuf[PCAP_ERRBUF_SIZE];
	char dev[100];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask, net;
	struct pcap_pkthdr* header;
    	const u_char* packet;

	const struct libnet_ethernet_hdr *ethernet;
	const struct libnet_ipv4_hdr *ip;
	const struct libnet_tcp_hdr *tcp;
	const char *payload;

	u_int size_ip;
	u_int size_tcp;
	u_int size_payload;

	if(pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return 1;
	}

	printf("\n-- List of available devices --\n");
	for(d = alldevs; d != NULL; d = d->next){
		printf("%d %s", ++i, d->name);
		if(d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i == 0){
		printf("\nNo interfaces found! Make sure Pcap is installed.\n");
		return 0;
	}	

	pcap_freealldevs(alldevs);
	

	printf("\nPlease type a device name from above... 	ex) eth0\n: ");
	scanf("%s", dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", dev);
		return -1;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}

	printf("Capturing %d packets from %s... (TCP/IP, Ethernet, port 80)\n", RPT, dev);
	for (rpt_count = 0; rpt_count < RPT; rpt_count++) {

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		printf("\n*************** No.%d packet captured ***************\n", rpt_count + 1);
		printf("%u bytes captured\n", header->caplen);

		//이더넷 헤더정보 출력
		ethernet = (struct libnet_ethernet_hdr*)(packet);
		printf("\nETHERNET HEADER\n============================\n");
		printf("MAC DST: ");
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			printf("%02x ", ethernet->ether_dhost[j]);
		}
		printf("\nMAC SRC: ");
		for(j = 0; j < ETHER_ADDR_LEN; j++) {
			printf("%02x ", ethernet->ether_shost[j]);
		}
		
		//IPv4 헤더정보 출력
		printf("\n\nIPv4 HEADER\n============================\n");
		ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20){
			printf("	* Invalid IP header length: %u bytes\n", size_ip);
			return 0;
		}
		printf("SRC IP ADDR: %s\n", inet_ntoa(ip->ip_src));
		printf("DST IP ADDR: %s\n", inet_ntoa(ip->ip_dst));

		//TCP 헤더정보 출력
		printf("\nTCP HEADER\n============================\n");
		tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
			return 0;
		}
		printf("Src Port: %d\n", ntohs(tcp->th_sport));
		printf("Dst Port: %d\n", ntohs(tcp->th_dport));

		//Data 출력
		payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		if(size_payload > 0) {
			printf("\nPayload (%d bytes):\n", size_payload);
			for(j = 0; j < size_payload; j++) {
				printf("%02x ", payload[j]);
				if(j == 15) break;
			}	
			printf("\n");
		}
		else
			printf("\nNo Payload.\n");
		printf("\n");
		//printf("caplen: %u, len: %d\n", header->caplen, header->len);
	}
	pcap_close(handle);
	return 0;
}
