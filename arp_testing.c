#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/packetg.h"

int main(){
    int generator;
    struct mac_field l2_field;
    struct arp_field l25_field;
    /* Request */
    struct packet_seed request_seed;
    char request_packet[MAX_PACKET_LENGTH];
    memset(request_packet, 0, MAX_PACKET_LENGTH);

    /* L2 */
    l2_field.src_addr = "00:00:00:00:00:01";
    l2_field.dst_addr = "ff:ff:ff:ff:ff:ff";

    l2_field.ether_type = ETH_P_ARP;

    /* ARP */
    l25_field.src_addr = "00:00:00:00:00:01";
    l25_field.dst_addr = "00:00:00:00:00:00";
    
    l25_field.src_ip_addr = "10.0.0.1";
    l25_field.dst_ip_addr = "10.0.0.2";
    
    l25_field.opcode = ARP_REQUEST;

    /* Setup socket */
    generator = init_packet_generator();
    request_seed.generator = generator;

    /* Prepare binding struct */
    struct sockaddr_ll request_sockaddr;
    request_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", &l2_field);
    request_seed.binding = request_sockaddr;

    /* Prepare a packet */
    /* header */
    unsigned short packet_size = 0;
    packet_size += push_l2_field(request_packet, &l2_field);
    packet_size += push_arp_field(request_packet, &l25_field);
    request_seed.total_len = packet_size;

    /* This packet is ready. */
    request_seed.packet = request_packet; 
    send_packet(&request_seed);

    /* Reply */
    char reply_packet[MAX_PACKET_LENGTH];
    memset(reply_packet, 0, MAX_PACKET_LENGTH);
    struct packet_seed reply_seed;

    /* L2 */
    l2_field.src_addr = "00:00:00:00:00:02";
    l2_field.dst_addr = "00:00:00:00:00:01";
    
    l2_field.ether_type = ETH_P_ARP;
    
    /* ARP */
    l25_field.src_addr = "00:00:00:00:00:02";
    l25_field.dst_addr = "00:00:00:00:00:01";

    l25_field.src_ip_addr = "10.0.0.2";
    l25_field.dst_ip_addr = "10.0.0.1";

    l25_field.opcode = ARP_REPLY;

    /* reply_seed and request_seed used the same socket. */
    reply_seed.generator = generator;

    /* Prepare binding struct */
    struct sockaddr_ll reply_sockaddr;
    reply_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", &l2_field);
    reply_seed.binding = reply_sockaddr;

    /* Prepare a packet */
    /* header */
    packet_size = 0;
    packet_size += push_l2_field(reply_packet, &l2_field);
    packet_size += push_arp_field(reply_packet, &l25_field);
    reply_seed.total_len = packet_size;

    /* This packet is ready. */
    reply_seed.packet = reply_packet; 
    send_packet(&reply_seed);
    return 0;
}