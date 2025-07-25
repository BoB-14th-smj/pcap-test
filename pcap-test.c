#include <netinet/in.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

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
	uint8_t data_value[21];
} Data;

//task 4 - print payload hex
void print_data(Data* data, uint32_t data_length){
	printf("==================DATA==================\n");

	//check data
	if(data_length <=0){
			printf("No Data\n");
			return;
	}

	//set range
	uint8_t limit;
	if (data_length >=20){
		limit = 20;
	}
	else{
		limit = data_length;
	}



	for(uint16_t i = 0 ; i < limit ; i++){
		uint8_t now = data->data_value[i];
		if(now != '\0'){
			printf("%x ", now);
		}
	}
	printf("\n");

}

//Detail1. only TCP
uint16_t check_ip_tcp(Ethernet* ethernet, Ip* ip){
	if(ethernet->ether_type != 0x0800){
		return 0;
	}
	if(ip->protocol !=0x06){
		return 0;
	}

	return 1;

}
void analysis_packet(struct pcap_pkthdr* header, const u_char* packet){

	//==================ETHERNET======================
	Ethernet* ethernet = get_ethernet_header(packet);
	packet = packet + 14;



	//==================IP======================
	Ip* ip = get_ip_header(packet);
	uint16_t total_length = ip->tolal_length;


	uint16_t tcp_offset_0 = (ip->header_length)*4;
	packet = packet + tcp_offset_0;


	if(!check_ip_tcp(ethernet,ip)){
		return;
	}


	//==================TCP======================


	Tcp* tcp = get_tcp_header(packet);
	uint16_t data_offset_0 = (tcp->data_offset)*4;
	packet = packet + data_offset_0;



	//==================DATA======================
	Data* data = (Data*) packet;
	uint32_t data_length =  total_length - tcp_offset_0 - data_offset_0;




	//==================PRINT======================

	//task 1 . src mac/ dst mac
	print_ethernet_header(ethernet);

	//task2. src ip / dst ip
	print_ip_header(ip);

	//task 3. src port / dst port
	print_tcp_header(tcp);
	print_data(data, data_length);

	printf("\n");
	printf("\n");









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
