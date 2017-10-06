# A Library of Packet Generator 
> For Linux

Follow those steps, and you will know how to use this library to send a packet!

[Example code](https://github.com/YanHaoChen/packetg/blob/master/src/packetg.c)

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
struct mac_addr *l2_addr;
struct ip_addr *l3_addr;
struct udp_addr *l4_addr;

/* A struct to store which sending a packet needs. */
struct packet_seed seed;

/* Initialize the packet which will be sent. */
char packet[1024];
memset(packet, 0, 1024);

/* Full in fields of L2 */
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

/* Full in fields of L3 */
l3_addr = (struct ip_addr*)malloc(sizeof(struct ip_addr));
l3_addr->src_addr = "10.0.0.1";
l3_addr->dst_addr = "10.0.0.2";

l3_addr->protocol = IPPROTO_UDP;

/* Full in fields of L4 */
l4_addr = (struct udp_addr*)malloc(sizeof(struct udp_addr));
l4_addr->src_port = 1234;
l4_addr->dst_port = 4321;
```


##### step 3
Initialize a socket.

```c
generator = init_packet_generator();
seed.generator = generator;
```

##### step 4
Select the interface you want to use, and get this struct(`sockaddr_ll`) which will be used when you send a packet to internet on this interface.

> This struct will bind a destination MAC which is equal to `l2_addr->dst_addr `.

```c
struct sockaddr_ll this_sockaddr;
this_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", l2_addr);
seed.binding = this_sockaddr;

```
##### step 5
Push L2, L3, UDP fields and payload into this packet.

```c
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