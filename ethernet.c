#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include "ethernet.h"



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

Ethernet* get_ethernet_header(const u_char* packet){
    Ethernet* ethernet;
    ethernet = (Ethernet*) packet;
    ethernet->ether_type = ntohs(ethernet->ether_type);
    return ethernet;
}
