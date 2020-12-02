#include "tcp-block.h"

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    get_my_mac(dev);
    char* block = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct packet_info *p_info = (struct packet_info*) packet;

        if(ntohs(p_info->ethernet.ether_type) != ETHERTYPE_IP){
            printf("not ip\n");
            continue;
        }
        if(p_info->ipv4.ip_p != IPPROTO_TCP){
            printf("not tcp\n");
            continue;
        }
        if(block_chk(p_info, block)){
            send_rst(handle,p_info);
            send_fin(handle,p_info);
        }
    }

    pcap_close(handle);
}
