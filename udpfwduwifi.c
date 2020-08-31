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

#include "duples.h"

#include <endian.h>

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
    unsigned int total_size = sizeof(struct duples_header) + sizeof(struct uwifi_packet);
    unsigned char *rspkt = calloc(1, total_size);
    struct duples_header *rhdr = (struct duples_header *)rspkt;
    struct uwifi_packet *upkt = (struct uwifi_packet *)(rspkt + sizeof(struct duples_header));
    int rsize = -1;
    
    //forwarding socket vars
    int outfd = -1;
    struct sockaddr_in destaddr;
    uint16_t d_port = 2345;

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
    //this may not be necessary
    ifctrl_iwget_interface_info(iface);
    memcpy(&iface->channel_set, &iface->channel, sizeof(iface->channel));

    if (!uwifi_init(iface))
    {
        LOG_ERR("Error during libuwifi initialization for interface %s.", iface->ifname);
        return 4;
    }
    
    //initialize the outgoing UDP socket
    outfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (outfd < 0)
    {
        LOG_ERR("Couldn't open outgoing UDP socket.");
        return 5;
    }

    memset(&destaddr, 0, sizeof(struct sockaddr_in));
    destaddr.sin_family = AF_INET;
    destaddr.sin_addr.s_addr = inet_addr(argv[2]);
    destaddr.sin_port = htons(d_port);

    //initialize the reusable packet variables
    rhdr->hdr_version = 1;
    rhdr->hdr_size = sizeof(struct duples_header);
    rhdr->le_src = (__BYTE_ORDER == __LITTLE_ENDIAN);
    rhdr->pload_type = DUPLES_PAYLOAD_UWIFI;
    rhdr->pload_size = htons(sizeof(struct uwifi_packet));

    while (true)
    {
        rsize =  packet_socket_recv(iface->sock, buffr, buffsize);
        if (rsize > 0)
        {
            memset(upkt, 0, sizeof(struct uwifi_packet));
            rsize = uwifi_parse_raw(buffr, rsize, upkt, iface->arphdr);
            if (rsize >= 0)
            {
                gettimeofday(&rhdr->cap_ts, NULL);
                rhdr->cap_ts.tv_sec = htonl(rhdr->cap_ts.tv_sec);
                rhdr->cap_ts.tv_usec = htonl(rhdr->cap_ts.tv_usec);
                //printf("sec: %d usec: %i rsize: %i\n", spkt->header.cap_ts.tv_sec, spkt->header.cap_ts.tv_usec, rsize);
                if (sendto(outfd, (const void *)rspkt, total_size, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) < 0)
                {
                    LOG_ERR("Error forwarding packet metadata.");
                    break;
                }
            }
        }
    }

    /* cleanup and exit */
    ifctrl_finish();
    uwifi_fini(iface);
    free(iface);
    free(buffr);
    free(rspkt);
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
