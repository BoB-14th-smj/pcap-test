#pragma once
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>


//Detail2~3. struct
typedef struct {
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    uint16_t ether_type;
} Ethernet;


void print_ethernet_header(Ethernet* ethernet);
Ethernet* get_ethernet_header(const u_char* packet);
