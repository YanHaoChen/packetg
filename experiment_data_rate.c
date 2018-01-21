#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_field l2_field;
    struct ip_field l3_field;
    struct udp_field l4_field;
    struct packet_seed seed_5M, seed_10M;
    seed_5M.last_packet = NULL;
    seed_10M.last_packet = NULL;

    char packet[MAX_PACKET_LENGTH];
    
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
    seed_5M.generator = generator;
    seed_10M.generator = generator;

    /* Prepare binding struct */
    struct sockaddr_ll this_sockaddr;
    this_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", &l2_field);
    seed_5M.binding = this_sockaddr;
    seed_10M.binding = this_sockaddr;

    /* Prepare a packet */
    /* header */
    unsigned short packet_size = 0;
    packet_size += push_l2_field(packet, &l2_field);
    packet_size += push_l3_field(packet, &l3_field);
    packet_size += push_udp_field(packet, &l4_field);
    seed_5M.header_len = packet_size;
    seed_10M.header_len = packet_size;

    /* payload */
    prepare_M_packets(&seed_5M, packet, 5);
    prepare_M_packets(&seed_10M, packet, 10);
    /* Calculate checksum and length */
    package_udp_packet_without_checksum(&seed_5M);
    package_udp_packet_without_checksum(&seed_10M);

    
    /* Send this packet */
    /* 10 second 5M */
    int state=0, i=0;
    for(i=0;i<5;i++){
        state = send_packets_in_1sec(&seed_5M, 1);
    }
    for(i=0;i<5;i++){
        state = send_packets_in_1sec(&seed_10M, 1);
    }
    sleep(5);
    for(i=0;i<5;i++){
        state = send_packets_in_1sec(&seed_5M, 1);
        state = send_packets_in_1sec(&seed_10M, 1);
    }
    return 0;
}
