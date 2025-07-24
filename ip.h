#pragma once
#include <stdint.h>
#include <pcap/pcap.h>

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

void print_ip_address(uint32_t ip_address);
void print_ip_header(Ip* ip);
Ip* get_ip_header(const u_char* packet);
