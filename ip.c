#include <stdio.h>
#include <stdint.h>
#include "ip.h"
#include <pcap/pcap.h>

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
