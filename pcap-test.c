#include <netinet/in.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>

void usage(){
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* device;
} Param;


Param param = {
	.device = NULL
};


typedef struct {
	uint8_t destination_mac_address[6];
	uint8_t source_mac_address[6];
	uint16_t ether_type;
} Ethernet;

typedef struct{
	uint8_t version : 4;
	uint8_t header_length : 4;
	uint8_t dscp : 6;
	uint8_t ecn : 2;

	uint16_t tolal_length;
	uint16_t identification;
	uint16_t flags : 3;
	uint16_t fragment_offset : 13;

	uint8_t ttl;
	uint8_t protocol;
	uint16_t header_checksum;

	uint32_t source_ip_address;
	uint32_t destination_ip_address;
}Ip;



void print_ethernet_header(Ethernet* ethernet){

	printf("===============Ethernet===============\n");

	printf("SRC MAC Address : ");
	for (uint16_t i =0 ;i<6;i++){
		printf("%02x ", ethernet->source_mac_address[i]);
	}
	printf("\n");

	printf("DES MAC Address : ");
	for (uint16_t i =0 ;i<6;i++){
		printf("%02x ", ethernet->destination_mac_address[i]);
	}
	printf("\n");

	// printf("ether type : 0x%04x\n", ethernet->ether_type);

}

void print_ip_address(uint32_t ip_address){
	uint32_t data = ip_address;
	uint32_t mask = 0xFF000000;
	uint32_t result = 0;
	for (uint16_t i =0; i<4 ; i++){
		result =  data & (mask >> i*8);
		printf("%d", result >> (3-i)*8);
		if(i!=3){
			printf(".");
		}

	}
	printf("\n");

}

void print_ip_header(Ip* ip){
	printf("==================IP==================\n");
	printf("SRC IP Address : ");
	print_ip_address(ip->source_ip_address);
	printf("DES IP Address : ");
	print_ip_address(ip->destination_ip_address);


}


Ethernet* get_ethernet_header(const u_char* packet){
	Ethernet* ethernet;
	ethernet = (Ethernet*) packet;
	ethernet->ether_type = ntohs(ethernet->ether_type);
	return ethernet;
}



Ip* get_ip_header(const u_char* packet){
	Ip* ip;
	ip = (Ip*) packet;

	// printf("%08x\n",ip->tolal_length);
	// uint8_t header_length = ip->tolal_length;
	// printf("%08x\n", ip->tolal_length);
	ip->source_ip_address = ntohl(ip->source_ip_address);
	ip->destination_ip_address = ntohl(ip->destination_ip_address);

	return ip;
}



void analysis_packet(struct pcap_pkthdr* header, const u_char* packet){
	Ethernet* ethernet = get_ethernet_header(packet);
	print_ethernet_header(ethernet);

	// if(ethernet->ether_type != 0x0800){
	// 	return ;
	// }

	packet = packet + 14;
	Ip* ip = get_ip_header(packet);
	print_ip_header(ip);


}


bool check_argu(Param* param, int argc, char* argv[]){
	if (argc != 2){
		usage();
		return false;
	}
	param->device = argv[1];
	return true;
}

int main(int argc, char** argv){
	if(!check_argu(&param,argc ,argv)){
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.device, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.device, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0){
			continue; //time out
		} else if(res <0){ // error
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		analysis_packet(header, packet);
		// printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);


}
