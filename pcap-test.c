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
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);


}
