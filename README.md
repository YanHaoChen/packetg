# A Library of Packet Generator 

This library for making generating packet easy.

> For Linux

## UDP

Follow those steps, and you will know how to use this library to send a UDP packet.

[Example code](https://github.com/YanHaoChen/packetg/blob/master/src/packetg_testing.c)

##### step 1

Include this header(packetg.h).

```c
#include "src/packetg.h"
```
##### step 2
Prepare some parameters(L2, L3 and L4) for sending a packet.

```c
/* Store socket descriptor. */
int generator;

/* Structs to store parameters for headers. */
struct mac_field *l2_field;
struct ip_field *l3_field;
struct udp_field *l4_field;

/* A struct to store which sending a packet needs. */
struct packet_seed seed;

/* Initialize the packet which will be sent. */
char packet[1024];
memset(packet, 0, 1024);

/* Full in fields of L2 */
l2_field = (struct mac_field*)malloc(sizeof(struct mac_field));
l2_field->src_addr = "00:00:00:00:00:01";
l2_field->dst_addr = "00:00:00:00:00:02";

l2_field->ether_type = ETH_P_IP;

/* Full in fields of L3 */
l3_field = (struct ip_field*)malloc(sizeof(struct ip_field));
l3_field->src_addr = "10.0.0.1";
l3_field->dst_addr = "10.0.0.2";

l3_field->protocol = IPPROTO_UDP;

/* Full in fields of L4 */
l4_field = (struct udp_field*)malloc(sizeof(struct udp_field));
l4_field->src_port = 1234;
l4_field->dst_port = 4321;
```


##### step 3
Initialize a socket.

```c
generator = init_packet_generator();
seed.generator = generator;
```

##### step 4
Select the interface you want to use, and get this struct(`sockaddr_ll`) which will be used when you send a packet to internet on this interface.

> This struct will bind a destination MAC which is equal to `l2_field->dst_addr `.

```c
struct sockaddr_ll this_sockaddr;
this_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", l2_field);
seed.binding = this_sockaddr;

```
##### step 5
Push L2, L3, UDP fields and payload into this packet.

```c
/* header */
unsigned short packet_size = 0;
packet_size += push_l2_field(packet, l2_field);
packet_size += push_l3_field(packet, l3_field);
packet_size += push_udp_field(packet, l4_field);
seed.header_len = packet_size;

/* payload */
struct packet_payload payload;
payload.content = "test";
payload.len = sizeof("test");
seed.total_len = push_payload(packet, seed.header_len, &payload);

/* This packet is ready. */
seed.packet = packet; 
```

##### step 6

Finally, calculate the checksum and langth, and write those values into ip and udp headers. 

```c
package_udp_packet_with_checksum(&seed);
```

##### step 7
Send this packet!

```c
send_packet(&seed);
```

## ARP(Request)

[Example code](https://github.com/YanHaoChen/packetg/blob/master/src/arp_testing.c)

