#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// definitions for internet operations(e.g. htons...)
#include <arpa/inet.h>
// sockaddr_ll
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
// struct ifreq, IFNAMSIZ
#include <net/if.h>

// struct of packet header
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// multi-process
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define L2_HEADER 14
// ARP HEADER + PADDING
#define ARP_HEADER 46
#define L3_HEADER 20
#define UDP_HEADER 8

//minimum maximum reassembly buffer size
#define K_MIN_MRBS 572
#define M_MAX_MRBS 1450

struct mac_field{
    unsigned char *src_addr;
    unsigned char *dst_addr;
    unsigned short ether_type;
};

struct __attribute__((__packed__)) arp_header{
    unsigned short hw_type;
    unsigned short protocol;
    unsigned char addr_len;
    unsigned char protocol_addr_len;
    unsigned short opcode;
    unsigned char sender_hw_addr[6];
    struct in_addr sender_ip;
    unsigned char target_hw_addr[6];
    struct in_addr target_ip;
};

enum{
    ARP_REQUEST=1,
    ARP_REPLY=2,
    RARP_REQUEST=3,
    RARP_REPLY=4
};

struct arp_field{
    unsigned char *src_addr;
    unsigned char *dst_addr;
    char *src_ip_addr;
    char *dst_ip_addr;
    unsigned short opcode;
};

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
	unsigned int repeat;
	struct packet_seed *last_packet;
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

void mac_addr_a_to_b_net(unsigned char *a_addr, unsigned char *b_net_addr){
    int i;
    for(i=0;i <= 5; i++){
        b_net_addr[i] = a_addr[5-i]; 
    }
}

int str_mac_addr_a_to_b_net(unsigned char *a_addr, unsigned char *b_net_addr){
    unsigned short second_c = 0;
    unsigned short first_c = 0;
    int i;
    int addr_count = 0;
    for(i=-1;i<17;i+=3){
        if(tolower(a_addr[i+1]) >= 97 && tolower(a_addr[i+1]) <= 102){
            second_c = (unsigned short)tolower(a_addr[i+1]) - 97;
        }else if(a_addr[i+1] >= 48 && a_addr[i+1] <= 57){
            second_c = (unsigned short)a_addr[i+1] - 48;
        }else{
            printf("error format:%c\n",a_addr[i+1]);
            return 1;
        }

        if(tolower(a_addr[i+2]) >= 97 && tolower(a_addr[i+2]) <= 102){
            first_c = (unsigned short)tolower(a_addr[i+2]) - 97;
        }else if(a_addr[i+2] >= 48 && a_addr[i+2] <= 57){
            first_c = (unsigned short)a_addr[i+2] - 48;
        }else{
            printf("error format:%c\n",a_addr[i+2]);
            return 1;
        }
        b_net_addr[addr_count] = (second_c << 4) + first_c;
        addr_count++;
    }
    return 0;
}

int init_packet_generator(void){
    int sockfd;
    if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("Establish socket: error\n");
        return -1;
    }
    return sockfd;
}

struct sockaddr_ll set_interface_and_get_binding_addr(int sockfd, char *interface_name , struct mac_field *field){
    struct ifreq if_id;
    struct sockaddr_ll bind_addr;   
    memset(&if_id, 0, sizeof(struct ifreq));

	strncpy(if_id.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_id) < 0){
        perror("Setting interface: error\n");
    }
    //mac_addr_a_to_b_net(field->dst_addr, bind_addr.sll_addr);
    str_mac_addr_a_to_b_net(field->dst_addr, bind_addr.sll_addr);
    bind_addr.sll_ifindex = if_id.ifr_ifindex;
    bind_addr.sll_halen = ETH_ALEN;
    return bind_addr;
}

/* Push field */

unsigned short push_l2_field(char *packet, struct mac_field *field){
    struct ether_header *l2_header = (struct ether_header *)packet;
    l2_header->ether_type = htons(field->ether_type);

    str_mac_addr_a_to_b_net(field->src_addr, l2_header->ether_shost);
    str_mac_addr_a_to_b_net(field->dst_addr, l2_header->ether_dhost);

    return L2_HEADER;
}

unsigned short push_arp_field(char *packet, struct arp_field *field){
    struct arp_header *arp_header = (struct arp_header *)(packet + L2_HEADER);
    // ethernet = 1
    arp_header->hw_type = htons(0x0001);
    // IP
    arp_header->protocol = htons(0x0800);
    arp_header->addr_len = 6;
    arp_header->protocol_addr_len = 4;
    arp_header->opcode = htons(field->opcode);
    
    str_mac_addr_a_to_b_net(field->src_addr ,arp_header->sender_hw_addr);
    inet_aton(field->src_ip_addr, &arp_header->sender_ip);
    str_mac_addr_a_to_b_net(field->dst_addr ,arp_header->target_hw_addr); 
    inet_aton(field->dst_ip_addr, &arp_header->target_ip);
    return ARP_HEADER;
}

unsigned short push_l3_field(char *packet, struct ip_field *field){
    struct ip *l3_header = (struct ip *)(packet + L2_HEADER);
    l3_header->ip_hl = 5;
    l3_header->ip_v = 4;
    l3_header->ip_tos = 0;
    l3_header->ip_len = 0;    
    l3_header->ip_id = htons(rand());
    l3_header->ip_ttl = 255;
    l3_header->ip_p = field->protocol;
    inet_aton(field->src_addr, &l3_header->ip_src);
	inet_aton(field->dst_addr, &l3_header->ip_dst);
    return L3_HEADER;  
}

unsigned short push_udp_field(char *packet, struct udp_field *field){
    struct udphdr *udp_header = (struct udphdr*)(packet+L2_HEADER+L3_HEADER);
    udp_header->uh_sport = htons(field->src_port);
    udp_header->uh_dport = htons(field->dst_port);
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
    if(seed->last_packet != NULL){
        package_l3_packet(seed->last_packet);
    }
    return 0;
}

int package_udp_packet_without_checksum(struct packet_seed *seed){
    struct ip *l3_header = (struct ip *)(seed->packet + L2_HEADER);
    l3_header->ip_len = htons(seed->total_len - L2_HEADER);
    l3_header->ip_sum = cal_checksum((unsigned short *)l3_header, L3_HEADER);
    
    struct udphdr *udp_header = (struct udphdr *)(seed->packet + L2_HEADER + L3_HEADER);
    int udp_len = seed->total_len - L2_HEADER - L3_HEADER;
    udp_header->uh_ulen = htons(udp_len);
    if(seed->last_packet != NULL){
        package_udp_packet_without_checksum(seed->last_packet);
    }
    return 0;
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
    if(seed->last_packet != NULL){
        package_udp_packet_with_checksum(seed->last_packet);
    }
    return 0;
}

/* Send */
int send_packet(struct packet_seed *seed, int show){
    struct timespec tms;
    if (sendto(seed->generator, seed->packet, seed->total_len, 0, (struct sockaddr*)&seed->binding, sizeof(struct sockaddr_ll)) < 0){
        perror("send_packet");
        return 1;
    } else {
        if(show){
            if(clock_gettime(CLOCK_REALTIME, &tms)){
                return 1;
            }
            long long int timestp = tms.tv_sec * 1000000;
            timestp += tms.tv_nsec/1000;
            printf("%lld,%d\n",timestp, seed->total_len);
        }
        return 0;
    }
}

void prepare_K_packets(struct packet_seed *seed,char *packet , unsigned int amount){
	unsigned int packet_needed = 0;
	packet_needed = (amount << 10) / K_MIN_MRBS;
	unsigned short last_packet_size = 0;
	last_packet_size= (amount << 10) % K_MIN_MRBS;
	unsigned short max_payload_size = K_MIN_MRBS - seed->header_len;
    int last_repeat = 0;
    int need_third_seed = 0;
    int third_seed_len = 0;
	if(last_packet_size > 0 && last_packet_size < 60){
        packet_needed -= 1;
        if((last_packet_size + K_MIN_MRBS) % 2 == 0 ){
        	last_repeat = 2;
            last_packet_size = (last_packet_size + K_MIN_MRBS) / 2;
        }else{
            need_third_seed = 1;
            last_repeat = 1;
            last_packet_size = (last_packet_size + K_MIN_MRBS) / 2;
            third_seed_len = last_packet_size + 1;
        }
	}

	char payload_packet[max_payload_size];
	memset(payload_packet,'1', max_payload_size);
	struct packet_payload payload;
	payload.content = payload_packet;
	payload.len = max_payload_size;
	seed->total_len = push_payload(packet, seed->header_len, &payload);
	seed->packet = packet;
    seed->repeat = packet_needed;

    if(last_packet_size != 0){
        struct packet_seed *second_seed;
        second_seed = (struct packet_seed *)malloc(sizeof(struct packet_seed));
	    second_seed->packet = packet;
        second_seed->header_len = seed->header_len;
        second_seed->total_len = last_packet_size;
        second_seed->generator = seed->generator;
        second_seed->binding = seed->binding;
        second_seed->repeat = last_repeat;
        second_seed->last_packet = NULL;
        if(need_third_seed == 1){
            struct packet_seed *third_seed;
            third_seed = (struct packet_seed *)malloc(sizeof(struct packet_seed));
	        third_seed->packet = packet;
            third_seed->header_len = seed->header_len;
            third_seed->total_len = third_seed_len;
            third_seed->generator = seed->generator;
            third_seed->binding = seed->binding;
            third_seed->repeat = 0;
            third_seed->last_packet = NULL;
            second_seed->last_packet = third_seed;
        }
        seed->last_packet = second_seed;
    }else{
        seed->last_packet = NULL;
    }
}

void prepare_M_packets(struct packet_seed *seed,char *packet , unsigned int amount){

	unsigned int packet_needed = 0;
	packet_needed = (amount << 20) / M_MAX_MRBS;
	unsigned short last_packet_size = 0;
	last_packet_size= (amount << 20) % M_MAX_MRBS;
	unsigned short max_payload_size = M_MAX_MRBS - seed->header_len;
    int last_repeat = 0;
    int need_third_seed = 0;
    int third_seed_len = 0;
	if(last_packet_size > 0 && last_packet_size < 60){
        packet_needed -= 1;
        if((last_packet_size + M_MAX_MRBS) % 2 == 0 ){
        	last_repeat = 2;
            last_packet_size = (last_packet_size + M_MAX_MRBS) / 2;
        }else{
            need_third_seed = 1;
            last_repeat = 1;
            last_packet_size = (last_packet_size + M_MAX_MRBS) / 2;
            third_seed_len = last_packet_size + 1;
        }
	}

	char payload_packet[max_payload_size];
	memset(payload_packet,'1', max_payload_size);
	struct packet_payload payload;
	payload.content = payload_packet;
	payload.len = max_payload_size;
	seed->total_len = push_payload(packet, seed->header_len, &payload);
	seed->packet = packet;
    seed->repeat = packet_needed;

    if(last_packet_size != 0){
        struct packet_seed *second_seed;
        second_seed = (struct packet_seed *)malloc(sizeof(struct packet_seed));
	    second_seed->packet = packet;
        second_seed->header_len = seed->header_len;
        second_seed->total_len = last_packet_size;
        second_seed->generator = seed->generator;
        second_seed->binding = seed->binding;
        second_seed->repeat = last_repeat;
        second_seed->last_packet = NULL;
        if(need_third_seed == 1){
            struct packet_seed *third_seed;
            third_seed = (struct packet_seed *)malloc(sizeof(struct packet_seed));
	        third_seed->packet = packet;
            third_seed->header_len = seed->header_len;
            third_seed->total_len = third_seed_len;
            third_seed->generator = seed->generator;
            third_seed->binding = seed->binding;
            third_seed->repeat = 0;
            third_seed->last_packet = NULL;
            second_seed->last_packet = third_seed;
        }
        seed->last_packet = second_seed;
    }else{
        seed->last_packet = NULL;
    }
}

int send_packets_in_1sec(struct packet_seed *seed, int process_count, int show){
	int i, repeat, parent_repeat, child_repeat, status;
	repeat = seed->repeat;
    child_repeat = repeat / process_count;
    parent_repeat = child_repeat +(repeat % process_count);
	clock_t end_t, start_t;
    
    pid_t pid,wpid;
    start_t = clock();

    for(i=0;i<process_count-1;i++){
        pid = fork();
        if(pid == 0){
            for(i =0;i<child_repeat;i++){
                send_packet(seed, show);
	        }
            exit(0);
        }else{
            continue;
        }
    }
    for(i =0;i<parent_repeat;i++){
        send_packet(seed, show);
	}
    while ((wpid = wait(&status)) > 0);
	if(seed->last_packet != NULL){
        if(seed->last_packet->repeat == 2){
            send_packet(seed->last_packet, show);
            send_packet(seed->last_packet, show);
        }else{
            send_packet(seed->last_packet, show);
            if((seed->last_packet)->last_packet != NULL){
                send_packet((seed->last_packet)->last_packet, show);
            }
        }
	}
	end_t = clock();
	int result = 0;	
	if((end_t - start_t) <= CLOCKS_PER_SEC){
		result =0;
	}else{
		result =1;
	}
	while((end_t - start_t) < CLOCKS_PER_SEC){
        end_t = clock();
    }
	return result;
}