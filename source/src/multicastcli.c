#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#if 0
#define MCAST_PORT 18000
#define MCAST_ADDR "224.0.0.254"
#define BUFF_SIZE 256
#define MCAST_INTERVAL 1

int main(int argc, char*argv[])
{

    int s;
    struct sockaddr_in local_addr;
    int err = -1;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        printf("socket()\n");
        return -1;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(MCAST_PORT);

    err = bind(s,(struct sockaddr*)&local_addr, sizeof(local_addr)) ;
    if (err < 0) {
        printf("bind()\n");
        return -2;
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MCAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0) {
        printf("setsockopt():IP_ADD_MEMBERSHIP\n");
        return -4;
    }

    int times = 0;
    int addr_len = 0;
    char buff[BUFF_SIZE];
    int n = 0;

    for(times = 0; times < 5; times++) {
        addr_len = sizeof(local_addr);
        memset(buff, 0, BUFF_SIZE);

        n = recvfrom(s, buff, BUFF_SIZE, 0,(struct sockaddr*)&local_addr,&addr_len);
        if (n == -1) {
            printf("recvfrom()\n");
        }

        printf("Recv %dst message from server:%s\n", times, buff);
        sleep(MCAST_INTERVAL);
    }

    err = setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    close(s);
    return 0;
}
#endif

