#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <stdlib.h>

#define MAC 0
#define IP 1
#define PORT 2


#pragma pack(push, 1)
typedef struct packet_info{
    struct libnet_ethernet_hdr ethernet;
    struct libnet_ipv4_hdr ipv4;
    struct libnet_tcp_hdr tcp;
}packet_info;
#pragma pack(pop)


uint16_t ip_checksum(struct libnet_ipv4_hdr* ip_hdr);
uint16_t tcp_checksum(struct packet_info *packet);
void send_rst(pcap_t* handle, struct packet_info *org_packet);
void send_fin(pcap_t* handle, struct packet_info *org_packet);
int block_chk(struct packet_info *packet, char* block);
void get_my_mac(char* dev);