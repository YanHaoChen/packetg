#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// definitions for internet operations(ex htons...)
#include <arpa/inet.h>
// sockaddr_ll
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
// struct ifreq, IFNAMSIZ
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define L2_HEADER 14
#define L3_HEADER 20
#define UDP_HEADER 8

struct mac_addr{
    unsigned char src_addr[6];
    unsigned char dst_addr[6];
    unsigned short ether_type;
};
struct ip_addr{
    char *src_addr;
    char *dst_addr;
    unsigned char protocol;
};

struct udp_addr{
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


unsigned short cal_checksum(unsigned short *buf, int header_size){
    unsigned long sum =0;

    while (header_size > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000){
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        header_size -= 2;
    }
    if ( header_size & 1 ){
        sum += *((unsigned short *)buf);
    }
    while((sum >> 16) > 0){
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return (unsigned short)(~sum);
}

unsigned short cal_udp_checksum(struct presudo_header *presudo_hdr , unsigned short *buf, int header_size){
    unsigned long sum = 0;
    int i = sizeof(struct presudo_header) / 2;
    unsigned short *presudo_tmp;
    presudo_tmp = (unsigned short *)presudo_hdr;

    for(; i > 0; i--){
        sum += *presudo_tmp++;
    }
    while (header_size > 1)
    {
            sum += *buf++;
            if (sum & 0x80000000)
                    sum = (sum & 0xFFFF) + (sum >> 16);
            header_size -= 2;
    }
    if ( header_size & 1 ){
        sum += *((unsigned short *)buf);
    }
    while((sum >> 16) > 0){
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return (unsigned short)(~sum);
}

int init_packet_generator(void){
    int sockfd;
    if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("Establish socket: error\n");
        return -1;
    }
    
    return sockfd;
}

struct sockaddr_ll set_interface_and_get_binding_addr(int sockfd, char *interface_name , struct mac_addr *addr){
    struct ifreq if_id;
    struct sockaddr_ll bind_addr;   
    memset(&if_id, 0, sizeof(struct ifreq));

	strncpy(if_id.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_id) < 0){
        perror("Setting interface: error\n");
    }

    bind_addr.sll_addr[0] = addr->dst_addr[5];
    bind_addr.sll_addr[1] = addr->dst_addr[4];
    bind_addr.sll_addr[2] = addr->dst_addr[3];
    bind_addr.sll_addr[3] = addr->dst_addr[2];
    bind_addr.sll_addr[4] = addr->dst_addr[1];
    bind_addr.sll_addr[5] = addr->dst_addr[0]; 
    
    bind_addr.sll_ifindex = if_id.ifr_ifindex;
    bind_addr.sll_halen = ETH_ALEN;
    return bind_addr;
}

/* Push field */

int push_l2_field(char *packet, struct mac_addr *addr){
    struct ether_header *l2_header = (struct ether_header *)packet;
    l2_header->ether_type = htons(addr->ether_type);

    l2_header->ether_shost[0] = addr->src_addr[5];
    l2_header->ether_shost[1] = addr->src_addr[4];
    l2_header->ether_shost[2] = addr->src_addr[3];
    l2_header->ether_shost[3] = addr->src_addr[2];
    l2_header->ether_shost[4] = addr->src_addr[1];
    l2_header->ether_shost[5] = addr->src_addr[0];

    l2_header->ether_dhost[0] = addr->dst_addr[5];
    l2_header->ether_dhost[1] = addr->dst_addr[4];
    l2_header->ether_dhost[2] = addr->dst_addr[3];
    l2_header->ether_dhost[3] = addr->dst_addr[2];
    l2_header->ether_dhost[4] = addr->dst_addr[1];
    l2_header->ether_dhost[5] = addr->dst_addr[0]; 
    
    return L2_HEADER;
}

int push_l3_field(char *packet, struct ip_addr *addr){
    struct ip *l3_header = (struct ip *)(packet + L2_HEADER);
    l3_header->ip_hl = 5;
    l3_header->ip_v = 4;
    l3_header->ip_tos = 0;
    l3_header->ip_len = 0;    
    l3_header->ip_id = htons(rand());
    l3_header->ip_ttl = 255;
    l3_header->ip_p = addr->protocol;
    inet_aton(addr->src_addr, &l3_header->ip_src);
	inet_aton(addr->dst_addr, &l3_header->ip_dst);
    return L3_HEADER;  
}

int push_udp_field(char *packet, struct udp_addr *addr){
    struct udphdr *udp_header = (struct udphdr*)(packet+L2_HEADER+L3_HEADER);
    udp_header->uh_sport = htons(addr->src_port);
    udp_header->uh_dport = htons(addr->dst_port);
    udp_header->uh_ulen = 0;
    udp_header->uh_sum = 0;
    return UDP_HEADER;
}

unsigned short push_payload(char *packet, unsigned short header_len, struct packet_payload *payload){
    char *packet_header_end = packet + header_len;
    strncpy(packet_header_end, payload->content, payload->len);
    return (header_len + payload->len);
}

/* Package packet */

int package_l3_packet(struct packet_seed *seed){
    struct ip *l3_header = (struct ip *)(seed->packet + L2_HEADER);
    l3_header->ip_len = htons(seed->total_len - L2_HEADER);
    l3_header->ip_sum = cal_checksum((unsigned short *)l3_header, L3_HEADER);
}

int package_udp_packet_without_checksum(struct packet_seed *seed){
    struct ip *l3_header = (struct ip *)(seed->packet + L2_HEADER);
    l3_header->ip_len = htons(seed->total_len - L2_HEADER);
    l3_header->ip_sum = cal_checksum((unsigned short *)l3_header, L3_HEADER);
    
    struct udphdr *udp_header = (struct udphdr *)(seed->packet + L2_HEADER + L3_HEADER);
    int udp_len = seed->total_len - L2_HEADER - L3_HEADER;
    udp_header->uh_ulen = htons(udp_len);
}

int package_udp_packet_with_checksum(struct packet_seed *seed){
    struct ip *l3_header = (struct ip *)(seed->packet + L2_HEADER);
    l3_header->ip_len = htons(seed->total_len - L2_HEADER);
    l3_header->ip_sum = cal_checksum((unsigned short *)l3_header, L3_HEADER);
    
    struct udphdr *udp_header = (struct udphdr *)(seed->packet + L2_HEADER + L3_HEADER);
    int udp_len = (unsigned short)seed->total_len - L2_HEADER - L3_HEADER;
    udp_header->uh_ulen =htons(udp_len);
    struct presudo_header *presudo_hdr;
    presudo_hdr = (struct presudo_header *)malloc(sizeof(struct presudo_header));
    presudo_hdr->src_ip = (unsigned long)(l3_header->ip_src.s_addr);
    presudo_hdr->dst_ip = (unsigned long)(l3_header->ip_dst.s_addr);
    presudo_hdr->protocol = htons(IPPROTO_UDP);
    presudo_hdr->len = htons(udp_len);
    udp_header->uh_sum=cal_udp_checksum(presudo_hdr, (unsigned short *)udp_header, udp_len);
}

/* Send */

int send_packet(struct packet_seed *seed){
    if (sendto(seed->generator, seed->packet, seed->total_len, 0, (struct sockaddr*)&seed->binding, sizeof(struct sockaddr_ll)) < 0){
        return 0;
    } else {
        return 1;
    }
}