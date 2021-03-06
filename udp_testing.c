#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_field l2_field;
    struct ip_field l3_field;
    struct udp_field l4_field;
    struct packet_seed seed;
    char packet[MAX_PACKET_LENGTH];
    seed.last_packet = NULL;
    
    memset(packet, 0, MAX_PACKET_LENGTH);

    /* Prepare values for headers. */
    /* L2 */
    l2_field.src_addr = "00:00:00:00:00:01";
    l2_field.dst_addr = "00:00:00:00:00:02";

    l2_field.ether_type = ETH_P_IP;

    /* L3 */
    l3_field.src_addr = "10.0.0.1";
    l3_field.dst_addr = "10.0.0.2";

    l3_field.protocol = IPPROTO_UDP;

    /* L4 */
    l4_field.src_port = 1234;
    l4_field.dst_port = 4321;
    
    /* Setup socket */
    generator = init_packet_generator();
    seed.generator = generator;
    
    /* Prepare binding struct */
    struct sockaddr_ll this_sockaddr;
    this_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", &l2_field);
    seed.binding = this_sockaddr;
    
    /* Prepare a packet */
    /* header */
    unsigned short packet_size = 0;
    packet_size += push_l2_field(packet, &l2_field);
    packet_size += push_l3_field(packet, &l3_field);
    packet_size += push_udp_field(packet, &l4_field);
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
    send_packet(&seed, 0);
    return 0;
}
