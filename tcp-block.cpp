#include "tcp-block.h"

const char *blockmsg = "blocked!!!";
char mymac[6];

int block_chk(struct packet_info *packet, char* block){
	int datalen = packet->ipv4.ip_len - (packet->ipv4.ip_hl * 4) - (packet->tcp.th_off * 4);
	uint8_t *tmp = (uint8_t*)((uint8_t*)&(packet->tcp) + packet->tcp.th_off * 4);
	int size = datalen - strlen(block);
	for(int i = 0; i < size; i++){
		if(!memcmp(tmp + i, block, strlen(block))){
			return 1;
		}
	}
	return 0;

}

void send_rst(pcap_t* handle, struct packet_info *org_packet){
	int size = sizeof(struct libnet_ethernet_hdr) + (org_packet->ipv4.ip_hl * 4) + (org_packet->tcp.th_off * 4);
	int org_datalen = org_packet->ipv4.ip_len - (org_packet->ipv4.ip_hl * 4) - (org_packet->tcp.th_off * 4);
	uint8_t *new_packet = (uint8_t*)malloc(size);
	memcpy(new_packet,org_packet,size);
	struct packet_info *rst_packet = (struct packet_info *)new_packet;
	
	//eth smac = my mac
	memcpy(rst_packet->ethernet.ether_shost, mymac, 6);
	
	//ip len = sizeof(ip_hdr) + sizeof(tcp)
	rst_packet->ipv4.ip_len = (org_packet->ipv4.ip_hl * 4) + (org_packet->tcp.th_off * 4);

	//tcp seq = org seq + org.tcp_data_size
	rst_packet->tcp.th_seq = org_packet->tcp.th_seq + org_datalen;

	//flag = rst + ack
	rst_packet->tcp.th_flags = TH_RST;

	//checksum
	ip_checksum(&(rst_packet->ipv4));
	tcp_checksum(rst_packet);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&rst_packet), size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(new_packet);
}
void send_fin(pcap_t* handle, struct packet_info *org_packet){
	int size = sizeof(struct libnet_ethernet_hdr) + (org_packet->ipv4.ip_hl * 4) + (org_packet->tcp.th_off * 4) + strlen(blockmsg);
	int org_datalen = org_packet->ipv4.ip_len - (org_packet->ipv4.ip_hl * 4) - (org_packet->tcp.th_off * 4);
	uint8_t *new_packet = (uint8_t*)malloc(size);
	memcpy(new_packet,org_packet,size);
	struct packet_info *fin_packet = (struct packet_info *)new_packet;

	//data쓰기
	memcpy((uint8_t*)&(fin_packet->tcp) + fin_packet->tcp.th_off * 4, blockmsg, strlen(blockmsg));

	//eth smac = my mac
	memcpy(fin_packet->ethernet.ether_shost, mymac, 6);

	//eth dmac = org mac
	memcpy(fin_packet->ethernet.ether_dhost, org_packet->ethernet.ether_shost, 6);

	//ip len = sizeof(ip_hdr) + sizeof(tcp)
	fin_packet->ipv4.ip_len = (org_packet->ipv4.ip_hl * 4) + (org_packet->tcp.th_off * 4);

	//ip ttl = org ttl
	fin_packet->ipv4.ip_ttl = 128;

	//ip sip = org sip
	fin_packet->ipv4.ip_src = org_packet->ipv4.ip_dst;

	//ip dip = org dip
	fin_packet->ipv4.ip_dst = org_packet->ipv4.ip_src;

	//tcp sport = org sport
	fin_packet->tcp.th_sport = org_packet->tcp.th_dport;

	//tcp dport = org dport
	fin_packet->tcp.th_dport = org_packet->tcp.th_sport;

	//tcp seq = org seq + org.tcp_data_size
	fin_packet->tcp.th_seq = org_packet->tcp.th_seq;

	//tcp ack = org ack
	fin_packet->tcp.th_ack = org_packet->tcp.th_seq + org_datalen;

	//flag = rst + ack
	fin_packet->tcp.th_flags = TH_FIN;

	//checksum
	ip_checksum(&(fin_packet->ipv4));
	tcp_checksum(fin_packet);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fin_packet), size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }	
    printf("blocked\n");
	free(new_packet);
}

//u_short : 2 u_int : 4 uint16_t : 2 uint32_t : 4 uint8_t : 1
uint16_t ip_checksum(struct libnet_ipv4_hdr* ip_hdr){
	uint16_t *raw = (uint16_t*)ip_hdr;
	uint32_t checksum = 0;
	int len = (ip_hdr->ip_hl * 4) / 2;
	ip_hdr->ip_sum = 0;
	for(int i = 0; i < len; i++){
		checksum += raw[i];
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	uint16_t ans = (~checksum & 0xffff);
	ip_hdr->ip_sum = ans;
	return (uint16_t) ans;
}

uint16_t tcp_checksum(struct packet_info *packet) {
	uint16_t *raw = (uint16_t*)&(packet->tcp);
	uint16_t len = packet->ipv4.ip_len - (packet->ipv4.ip_hl * 4);
	uint32_t checksum = 0;
	uint16_t ans = 0;

	int nlen = len >> 1;
	packet->tcp.th_sum = 0;

	for(int i = 0; i < nlen; i++){
		checksum += raw[i];
	}
	if(len % 2 == 1){
		checksum += raw[nlen] & 0x00ff;
	}
	uint16_t* sip = (uint16_t*) &(packet->ipv4.ip_src);
	uint16_t* dip = (uint16_t*) &(packet->ipv4.ip_dst);
	for(int i = 0; i < 2; i++){
		checksum += sip[i];
		checksum += dip[i];
	}

	checksum += htons(6);
	checksum += htons(len);

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	ans = (~checksum & 0xffff);

	packet->tcp.th_sum = ans;
	return (uint16_t) ans;
}

void get_my_mac(char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    
    memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);   
}


















