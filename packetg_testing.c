#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_addr *l2_addr;
    struct ip_addr *l3_addr;
    struct udp_addr *l4_addr;
    struct packet_seed seed;
    char packet[MAX_PACKET_LENGTH];
    
    memset(packet, 0, MAX_PACKET_LENGTH);

    /* Prepare values for headers. */
    /* L2 */
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

    /* L3 */
    l3_addr = (struct ip_addr*)malloc(sizeof(struct ip_addr));
    l3_addr->src_addr = "10.0.0.1";
    l3_addr->dst_addr = "10.0.0.2";

    l3_addr->protocol = IPPROTO_UDP;

    /* L4 */
    l4_addr = (struct udp_addr*)malloc(sizeof(struct udp_addr));
    l4_addr->src_port = 1234;
    l4_addr->dst_port = 4321;
    
    /* Setup socket */
    generator = init_packet_generator();
    seed.generator = generator;
    
    /* Prepare binding struct */
    struct sockaddr_ll this_sockaddr;
    this_sockaddr = set_interface_and_get_binding_addr(generator, "enp0s3", l2_addr);
    seed.binding = this_sockaddr;
    
    /* Prepare a packet */
    /* header */
    unsigned short packet_size = 0;
    packet_size += push_l2_field(packet, l2_addr);
    packet_size += push_l3_field(packet, l3_addr);
    packet_size += push_udp_field(packet, l4_addr);
    seed.header_len = packet_size;

    /* payload */
    struct packet_payload payload;
    payload.content = "test";
    payload.len = sizeof("test");
    seed.total_len = push_payload(packet, seed.header_len, &payload);
    
    /* This packet is ready. */
    seed.packet = packet; 

    /* Calculate checksum and length */
    package_udp_packet_with_checksum(&seed);
    
    /* Send this packet */
    send_packet(&seed);
    return 0;
}
