#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define MAX_PACKET_LENGTH 8192

#define L2_HEADER 14
#define L3_HEADER 20
#define UDP_HEADER 8

/*
ether_type:
ETH_P_IP
ETH_P_ARP
...
Others can be found in if_ether.h.  
*/
struct mac_field{
    unsigned char src_addr[6];
    unsigned char dst_addr[6];
    unsigned short ether_type;
};
/*
protocol:
IPPROTO_IP 0
IPPROTO_UDP 17
IPPROTO_TCP 6
...
Others can be found in:
https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers 
*/
struct ip_field{
    char *src_addr;
    char *dst_addr;
    unsigned char protocol;
};

struct udp_field{
    unsigned short src_port;
    unsigned short dst_port;
};

struct packet_payload{
    char *content;
    unsigned short len;
};

struct packet_seed{
    char *packet;
    unsigned short header_len;
    unsigned short total_len;
    int generator;
    struct sockaddr_ll binding;
};

struct presudo_header {
    unsigned short protocol;
    unsigned short len;
    unsigned long src_ip;
    unsigned long dst_ip;
};

unsigned short cal_checksum(unsigned short *buf, int header_size);
void mac_addr_a_to_b_net(unsigned char *a_addr, unsigned char *b_net_addr);
int init_packet_generator(void);    
struct sockaddr_ll set_interface_and_get_binding_addr(int sockfd, char *interface_name , struct mac_field *field);

unsigned short push_l2_field(char *packet, struct mac_field *field);
unsigned short push_l3_field(char *packet, struct ip_field *field);
unsigned short push_udp_field(char *packet, struct udp_field *field);
unsigned short push_payload(char *packet, unsigned short header_len, struct packet_payload *payload);

int package_l3_packet(struct packet_seed *seed);
int package_udp_packet_without_checksum(struct packet_seed *seed);
int package_udp_packet_with_checksum(struct packet_seed *seed);

int send_packet(struct packet_seed *seed);