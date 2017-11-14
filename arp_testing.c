#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_field *l2_field;
    struct arp_field *l25_field;

    struct packet_seed seed;
    char packet[MAX_PACKET_LENGTH];
    memset(packet, 0, MAX_PACKET_LENGTH);

    /* L2 */
    l2_field = (struct mac_field*)malloc(sizeof(struct mac_field));
    l2_field->src_addr = "00:00:00:00:00:01";
    l2_field->dst_addr = "00:00:00:00:00:02";

    l2_field->ether_type = ETH_P_ARP;

    /* ARP */
    l25_field = (struct arp_field*)malloc(sizeof(struct arp_field));
    l25_field->src_addr = "00:00:00:00:00:01";
    l25_field->dst_addr = "00:00:00:00:00:00";
    
    l25_field->src_ip_addr = "10.0.0.1";
    l25_field->dst_ip_addr = "10.0.0.2";
    
    l25_field->opcode = ARP_REQUEST;

    /* Setup socket */
    generator = init_packet_generator();
    seed.generator = generator;

    /* Prepare binding struct */
    struct sockaddr_ll this_sockaddr;
    this_sockaddr = set_interface_and_get_binding_addr(generator, "enp0s3", l2_field);
    seed.binding = this_sockaddr;

    /* Prepare a packet */
    /* header */
    unsigned short packet_size = 0;
    packet_size += push_l2_field(packet, l2_field);
    packet_size += push_arp_field(packet, l25_field);
    seed.total_len = packet_size;

    /* This packet is ready. */
    seed.packet = packet; 
    send_packet(&seed);
    return 0;
}