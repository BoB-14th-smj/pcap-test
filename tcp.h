#pragma once
#include <stdint.h>
#include <netinet/in.h>


typedef struct{
    uint16_t source_port;
    uint16_t destination_port;

    uint32_t sequence_number;
    uint32_t acknoledgement_number;

    uint8_t reserved:4;
    uint8_t data_offset:4;

    uint8_t flags;
    uint16_t window;

    uint16_t checksum;
    uint16_t urgent_pointer;

}Tcp;



Tcp* get_tcp_header(const u_char* packet);
void print_tcp_header(Tcp* tcp);
