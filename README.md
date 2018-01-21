# A Library of Packet Generator 

This library for making generating packet easy.

> For Linux

## UDP

Follow those steps, and you will know how to use this library to send a UDP packet.

[Example code](https://github.com/YanHaoChen/packetg/blob/master/src/udp_testing.c)

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
struct mac_field l2_field;
struct ip_field l3_field;
struct udp_field l4_field;

/* A struct to store which sending a packet needs. */
struct packet_seed seed;
seed.last_packet=NULL;
/* Initialize the packet which will be sent. */
char packet[1024];
memset(packet, 0, 1024);

/* Fill in fields of L2 */
l2_field.src_addr = "00:00:00:00:00:01";
l2_field.dst_addr = "00:00:00:00:00:02";

l2_field.ether_type = ETH_P_IP;

/* Fill in fields of L3 */
l3_field.src_addr = "10.0.0.1";
l3_field.dst_addr = "10.0.0.2";

l3_field.protocol = IPPROTO_UDP;

/* Fill in fields of L4 */
l4_field.src_port = 1234;
l4_field.dst_port = 4321;
```


##### step 3
Initialize a socket.

```c
generator = init_packet_generator();
seed.generator = generator;
```

##### step 4
Select the interface you want to use, and get this struct(`sockaddr_ll`) which will be used when you send a packet to internet on this interface.

> This struct will bind a destination MAC which is equal to `l2_field.dst_addr `.

```c
struct sockaddr_ll this_sockaddr;
this_sockaddr = set_interface_and_get_binding_addr(generator, "eth0", &l2_field);
seed.binding = this_sockaddr;

```
##### step 5
Push L2, L3, UDP fields and payload into this packet.

```c
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
```

##### step 6

Finally, calculate the checksum and langth, and write those values into ip and udp headers. 

```c
package_udp_packet_with_checksum(&seed);
```

##### step 7

Send this packet!

```c
send_packet(&seed, 0);
```

> If the second argument is 1, packetg will display the end of  time and amount of bytes at this time.

##### step 8

Compile your code with packetg.

```shell
$ cc udp_testing.c src/packetg.c
```

##### step 9
Execute!

```shell
$ sudo ./a.out
```

## ARP

Most steps in generating ARP packet are the same as steps in generating UDP packet. At this section, I wrote down the steps which are different from generating UDP packet.

[Example code](https://github.com/YanHaoChen/packetg/blob/master/src/arp_testing.c)

##### Change L2 field

First of all, change the `ethernet_type` into `ETH_P_ARP`. 

```c
l2_field.ether_type = ETH_P_ARP;
```
If you want to generate ARP request, you need to fill in `dst_addr` with `ff:ff:ff:ff:ff:ff`.

```c

l2_field.src_addr = "00:00:00:00:00:01";
l2_field.dst_addr = "ff:ff:ff:ff:ff:ff";

l2_field.ether_type = ETH_P_ARP;
```
> `ff:ff:ff:ff:ff:ff` represents broadcast.

##### Prepare ARP field

When we generate a ARP request, we have to fill in `dst_addr` with `00:00:00:00:00:00`, and `opcode` with `ARP_REQUEST`.

```c
struct arp_field l25_field;

l25_field.src_addr = "00:00:00:00:00:01";
l25_field.dst_addr = "00:00:00:00:00:00";
    
l25_field.src_ip_addr = "10.0.0.1";
l25_field.dst_ip_addr = "10.0.0.2";
    
l25_field.opcode = ARP_REQUEST;
```

##### Set total length of seed

Because ARP packet doesn't have payload, the total length of seed is the same as length of header.

```c
/* header */
packet_size = 0;
packet_size += push_l2_field(request_packet, &l2_field);
packet_size += push_arp_field(request_packet, &l25_field);
request_seed.total_len = packet_size;
```

## With Constant Data Rate

Sometimes, we have to send our packets constantly(for example, send 30MB of data per second to a host). At thesituation, we can use three functions(`prepare_K_packets`, `prepare_M_packets` and `send_packets_in_1sec`) in `packetg` to make it.

[Example code](https://github.com/YanHaoChen/packetg/blob/master/data_rate_testing.c)

The functions of generating payload and sending packets are the main difference between generating single packet and generating packets constantly.



```C
/* payload */
/* prepare_M_packets will put the packet into the seed.packet and calculate the number packetg needs to repeat. The last packet will be put into seed.last_packet. */
prepare_M_packets(&seed, packet, 30);

/* Calculate checksum and length */
package_udp_packet_with_checksum(&seed);

/* Send this packet */
/*  state=0 -> In time ; state=1 -> Time out */
int state=0;
state = send_packets_in_1sec(&seed, 1);
```

 