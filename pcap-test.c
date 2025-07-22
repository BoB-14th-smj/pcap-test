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


void print_ethernet_header(Ethernet* ethernet){

	printf("===============Ethernet===============\n");

	printf("DES MAC Address : ");
	for (uint16_t i =0 ;i<6;i++){
		printf("%02x ", ethernet->destination_mac_address[i]);
	}
	printf("\n");


	printf("SRC MAC Address : ");
	for (uint16_t i =0 ;i<6;i++){
		printf("%02x ", ethernet->source_mac_address[i]);
	}
	printf("\n");

	printf("ether type : 0x%04x\n", ethernet->ether_type);








}

Ethernet* get_ethernet_header(const u_char* packet){
	Ethernet* ethernet;
	ethernet = (Ethernet*) packet;
	ethernet->ether_type = ntohs(ethernet->ether_type);
	print_ethernet_header(ethernet);

	return ethernet;
}


void analysis_packet(struct pcap_pkthdr* header, const u_char* packet){
	Ethernet* ethernet = get_ethernet_header(packet);

	if(ethernet->ether_type != 0x0800){
		return ;
	}

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
