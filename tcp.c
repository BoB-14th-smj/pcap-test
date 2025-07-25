#include <netinet/in.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include "tcp.h"


void print_tcp_bit(uint8_t value){
    uint8_t filter = 0x80;

    for(uint8_t i=0 ;i<8;i++){
        if(value & filter){
            printf("1");
        }
        else{
            printf("0");
        }
        filter = filter >> 1;

    }
    printf("\n");

}

void print_tcp_header(Tcp* tcp){
    printf("==================TCP==================\n");
    printf("SRC Port : ");
    printf("%d\n", tcp->source_port);
    printf("DES Port : ");
    printf("%d\n", tcp->destination_port);

    printf("%u\n", ntohl(tcp->sequence_number));
    printf("%u\n",ntohl( tcp->acknoledgement_number));
    // print_tcp_bit(tcp->data_offset);
    printf("%d\n", tcp->data_offset);
}


Tcp* get_tcp_header(const u_char* packet){
    Tcp* tcp;
    tcp = (Tcp*) packet;
    tcp->source_port = ntohs(tcp->source_port);
    tcp->destination_port = ntohs(tcp->destination_port);
    return tcp;
}
