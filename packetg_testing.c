#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_addr *l2_addr;
    struct ip_addr *l3_addr;
    struct udp_addr *l4_addr;
    char packet[1024];
    memset(packet, 0, 1024);
    l2_addr = (struct mac_addr*)malloc(sizeof(struct mac_addr));
    (l2_addr->src_addr)[0] = 0x01;
    (l2_addr->src_addr)[1] = 0x00;
    (l2_addr->src_addr)[2] = 0x00;
    (l2_addr->src_addr)[3] = 0x00;
    (l2_addr->src_addr)[4] = 0x00;
    (l2_addr->src_addr)[5] = 0x00;

    (l2_addr->dst_addr)[0] = 0x02;
    (l2_addr->dst_addr)[1] = 0x00;
    (l2_addr->dst_addr)[2] = 0x00;
    (l2_addr->dst_addr)[3] = 0x00;
    (l2_addr->dst_addr)[4] = 0x00;
    (l2_addr->dst_addr)[5] = 0x00;

    l2_addr->ether_type = ETH_P_IP;

    l3_addr = (struct ip_addr*)malloc(sizeof(struct ip_addr));
    l3_addr->src_addr = "10.0.0.1";
    l3_addr->dst_addr = "10.0.0.2";

    l3_addr->protocol = IPPROTO_UDP;

    l4_addr = (struct udp_addr*)malloc(sizeof(struct udp_addr));
    l4_addr->src_port = 1234;
    l4_addr->dst_port = 4321;
    
    generator = init_packet_generator();
    struct sockaddr_ll this_sockaddr;
    this_sockaddr = set_interface_and_get_binding_addr(generator, "enp0s3", l2_addr);
    
    int header_size = 0;
    header_size += push_l2_field(packet, l2_addr);
    header_size += push_l3_field(packet, l3_addr);
    header_size += push_udp_field(packet, l4_addr);
    packet[header_size++] = 't';
    packet[header_size++] = 'e';
    packet[header_size++] = 's';
    packet[header_size++] = 't';
    struct packet_seed seed;
    seed.generator = generator;
    seed.packet = packet;
    seed.len = header_size;
    seed.binding = this_sockaddr;

    package_udp_packet_with_checksum(&seed);
    send_packet(&seed);
    return 0;
}
