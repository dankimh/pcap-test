#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#define WORD32_SIZE 4

constexpr size_t MAX_PAYLOAD_SIZE=0x10;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_ether_mac(const struct libnet_ethernet_hdr* ethernet_header){
    	printf("Ethernet - src mac: %s\n",ether_ntoa((ether_addr*)ethernet_header->ether_shost));
   	printf("Ethernet - dst mac: %s\n",ether_ntoa((ether_addr*)ethernet_header->ether_dhost));
	return;
}
void print_ip(const struct libnet_ipv4_hdr* ipv4_header){
    	struct in_addr src=ipv4_header->ip_src;
    	struct in_addr dst=ipv4_header->ip_dst;
    	printf("IP - src ip: %s\n", inet_ntoa(src));
    	printf("IP - dst ip: %s\n", inet_ntoa(dst));
	return;
}

void print_port(const struct libnet_tcp_hdr* tcp_header){
    	u_int16_t src=tcp_header->th_sport;
    	u_int16_t dst=tcp_header->th_dport;
    	printf("TCP - src port: %u\n",ntohs(src));
   	printf("TCP - dst port: %u\n",ntohs(dst));
	return;
}

void print_payload(const u_char* payload,size_t payload_size){
    	size_t print_size=payload_size<MAX_PAYLOAD_SIZE?payload_size:MAX_PAYLOAD_SIZE;
    	printf("Payload (%zu byte(s)): ",payload_size);
    	for(size_t i=0;i<print_size;i++){
        	printf("%02x ",payload[i]);
    	}
    	if(payload_size>print_size)printf("...");
    	printf("\n");
	return;
}
int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
        	return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        	}
		printf("%u bytes captured\n", header->caplen);

        	struct libnet_ethernet_hdr* ethernet_header=(libnet_ethernet_hdr*)packet;
        	if(ntohs(ethernet_header->ether_type)!=ETHERTYPE_IP){
            		//not an ip protocol
            		printf("Not an ip protocol!\n");
            		printf("---------------------------------\n\n");
            		continue;
        	}

        	struct libnet_ipv4_hdr* ipv4_header=(libnet_ipv4_hdr*)(ethernet_header+1);
        	if(ipv4_header->ip_p!=IPPROTO_TCP){
            		//not a tcp protocol
            		printf("Not a tcp protocol!\n");
            		printf("---------------------------------\n\n");
            		continue;
        	}

        	struct libnet_tcp_hdr* tcp_header=(libnet_tcp_hdr*)(ipv4_header+1);

        	const u_int8_t tcp_header_size=(tcp_header->th_off)*WORD32_SIZE;
        	size_t header_size=sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr)+(size_t)tcp_header_size;

        	const u_char* payload=(u_char*)(tcp_header)+tcp_header_size;

        	print_ether_mac(ethernet_header);
        	print_ip(ipv4_header);
        	print_port(tcp_header);
        	print_payload(payload,(size_t)header->caplen-header_size);
        	printf("---------------------------------\n\n");
	}

	pcap_close(pcap);
}
