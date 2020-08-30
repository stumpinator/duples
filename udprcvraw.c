#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include <uwifi/conf.h>
#include <uwifi/raw_parser.h>
#include <uwifi/log.h>
#include <uwifi/packet_sock.h>
#include <uwifi/wlan_parser.h>
#include <uwifi/ifctrl.h>
#include <uwifi/inject.h>

#include "duples.h"

//#include <endian.h>

//socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//log level
static int MYLL = LL_INFO;

int main(int argc, char **argv) {
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    unsigned int buffsize = 4096; //size of buffer for packets
    unsigned char *buffr = calloc(1, buffsize); //packet buffer
    unsigned int total_size = 0; //sizeof(struct duples_header) + payload size
    struct duples_header *rhdr; // = (struct duples_header *)rspkt;
    int rsize = -1;
    
    //socket vars
    int sockfd = -1;
    struct sockaddr_in servaddr, clientaddr;
    uint16_t d_port = 2345;
    struct iovec iov; //used for recvmsg
    struct msghdr message; //used for recvmsg

    if (argc < 4)
    {
        LOG_ERR("usage: %s <iface> <host/ip> <port>", argv[0]);
        printf("example: %s mon0 127.0.0.1 2345\n", argv[0]);
        return 1;
    }

    if (sscanf(argv[3], "%hu", &d_port) != 1)
    {
        LOG_ERR("Invalid argument (%s) for port.", argv[3]);
        return 2;
    }

    strncpy(iface->ifname, argv[1], IF_NAMESIZE);
    LOG_INF("Using interface %s", iface->ifname);

    if (!ifctrl_init())
    {
        LOG_ERR("Error occured initializing interface control.");
        return 3;
    }

    //this stops the initialization from changing to anything different
    //default behavior of initialization is to set max bandwidth (HT40+/-)
    //this may not be necessary, but channel config should be handled elsewhere
    ifctrl_iwget_interface_info(iface);
    memcpy(&iface->channel_set, &iface->channel, sizeof(iface->channel));

    if (!uwifi_init(iface))
    {
        LOG_ERR("Error during libuwifi initialization for interface %s.", iface->ifname);
        return 4;
    }
    
    //initialize the UDP socket to listen on
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        LOG_ERR("Couldn't open outgoing UDP socket.");
        return 5;
    }

    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    memset(&clientaddr, 0, sizeof(struct sockaddr_in));
    memset(&iov, 0, sizeof(iov));
    memset(&message, 0, sizeof(message));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(argv[2]);
    servaddr.sin_port = htons(d_port);

    iov.iov_base = buffr;
    iov.iov_len = buffsize;
    message.msg_name = &clientaddr;
    message.msg_namelen = sizeof(clientaddr);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = 0;
    message.msg_controllen = 0;

    
    rsize = bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    if (rsize != 0)
    {
        LOG_ERR("Error binding to %s:%s", argv[2], argv[3]);
        return 6;
    }

    while (true)
    {
        rsize = recvmsg(sockfd, &message, 0);
        if (rsize > 0)
        {
            rsize = send(iface->sock, buffr, rsize, MSG_DONTWAIT);
            if (rsize == -1)
            {
                LOG_ERR("Error occured sending message over interface %s", iface->ifname);
            }
            else
            {
                LOG_INF("Sent %i bytes", rsize);
            }
        }
    }

    /* cleanup and exit */
    ifctrl_finish();
    uwifi_fini(iface);
    free(iface);
    free(buffr);
    return 0;
}

void __attribute__ ((format (printf, 2, 3)))
log_out(enum loglevel ll, const char *fmt, ...)
{
    if (MYLL >= ll)
    {
        va_list args;
        va_start(args, fmt);
        switch (ll)
        {
            case LL_CRIT:
            case LL_ERR:
                vfprintf(stderr, fmt, args);
                fprintf(stderr, "\n");
                break;
            case LL_WARN:
            case LL_NOTICE:
            case LL_INFO:
            case LL_DEBUG:
                vfprintf(stdout, fmt, args);
                fprintf(stdout, "\n");
            default:
                break;
        }
    }

    return;
}
