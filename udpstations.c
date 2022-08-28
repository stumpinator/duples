#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include "uwifi/conf.h"
#include "uwifi/log.h"
#include "uwifi/wlan_parser.h"
#include "uwifi/ifctrl.h"
#include "uwifi/channel.h"
#include "uwifi/netdev.h"

#include "duples.h"

#include <endian.h>

//socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//log level
static int MYLL = LL_INFO;
//loop flag
static bool CONTINUE_PROCESSING = true;

struct udpstatus_opts
{
    char *ifname;
    struct in_addr daddr;
    uint16_t dport;
    uint16_t loglevel;
    bool daemonize;
};

bool parseopts(int argc, char **argv, struct udpstatus_opts *myopts)
{
    int opt = 0;
    
    memset(myopts, 0, sizeof(struct udpstatus_opts));
    myopts->daemonize = false;
    myopts->loglevel = MYLL;
    myopts->dport = 2412;
    inet_aton("127.0.0.1", &myopts->daddr);

    while ((opt = getopt(argc, argv, ":i:d:p:l:s")) != -1)
    {
        switch(opt)
        {
            case 'i':
                myopts->ifname = optarg;
                break;
            case 'd':
                if ((inet_aton(optarg, &myopts->daddr)) == 0)
                {
                    return false;
                }
                break;
            case 'p':
                if (sscanf(optarg, "%hu", &myopts->dport) != 1)
                {
                    return false;
                }
                break;
            case 'l':
                if (sscanf(optarg, "%hu", &myopts->loglevel) != 1)
                {
                    return false;
                }
                break;
            case 's':
                myopts->daemonize = true;
                break;
            case ':':
            case '?':
            default:
                return false;
        }
    }

    //ensure log level falls in proper range (LL_CRIT to LL_DEBUG)
    myopts->loglevel = (myopts->loglevel < LL_CRIT) ? LL_CRIT : myopts->loglevel;
    myopts->loglevel = (myopts->loglevel > LL_DEBUG) ? LL_DEBUG : myopts->loglevel;

    if (myopts->ifname == NULL)
    {
        return false;
    }
    return true;
}

static void sig_handler(int signumber)
{
    switch(signumber)
    {
        case SIGHUP:
            LOG_DBG("Caught SIGHUP");
            break;
        case SIGINT:
        case SIGTERM:
        default:
            LOG_DBG("Caught signal");
            CONTINUE_PROCESSING = false;
    }
}

int main(int argc, char **argv) {
    struct udpstatus_opts myopts;
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    unsigned int buffsize = 4096; //size of buffer for packets
    unsigned char *buffr = calloc(1, buffsize); //packet buffer
    size_t total_size = sizeof(struct duples_header) + sizeof(struct duples_stations);
    unsigned char *rspkt = calloc(1, total_size);
    struct duples_header *dhdr = (struct duples_header *)rspkt;
    struct duples_stations *stapkt = (struct duples_stations *)(rspkt + sizeof(struct duples_header));
    size_t dynamic_size = 0;
    unsigned char iface_mac[6];

    //forwarding socket vars
    int outfd = -1;
    struct sockaddr_in destaddr;

    if (!parseopts(argc, argv, &myopts))
    {
        printf("example: %s -i wifi0 [-d 127.0.0.1] [-p 2345] [-l 3] [-s]\n", argv[0]);
        printf("-i      interface to gather station and frequency info. required\n");
        printf("-d      IP to send UDP packets. default 127.0.0.1\n");
        printf("-p      port to send UDP packets. default 2412\n");
        printf("-l      log level 2(CRIT) - 7(DEBUG). default 3(ERROR). DEBUG requires compile flag\n");
        printf("-s      run as service (daemonize). currently not implemented\n");
        return 1;
    }
    
    MYLL = myopts.loglevel;
    strncpy(iface->ifname, myopts.ifname, IF_NAMESIZE);
    LOG_INF("Using interface %s", iface->ifname);

    if (!ifctrl_init())
    {
        LOG_ERR("Error occured initializing interface control.");
        return 3;
    }

    if (!netdev_get_mac_address(iface->ifname, stapkt->iface_mac))
    {
        LOG_ERR("Error occured getting MAC address.");
        return 3;
    }

    //initialize the outgoing UDP socket
    outfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (outfd < 0)
    {
        LOG_ERR("Couldn't open outgoing UDP socket.");
        return 5;
    }

    //destination address
    memset(&destaddr, 0, sizeof(struct sockaddr_in));
    destaddr.sin_family = AF_INET;
    destaddr.sin_port = htons(myopts.dport);
    destaddr.sin_addr = myopts.daddr;

    //initialize the reusable packet variables
    dhdr->hdr_version = 1;
    dhdr->hdr_size = sizeof(struct duples_header);
    dhdr->le_src = (__BYTE_ORDER == __LITTLE_ENDIAN);
    dhdr->pload_type = DUPLES_PAYLOAD_STATIONS;
    dhdr->pload_size = 0;

    //register signals
    if (signal(SIGINT, sig_handler) == SIG_ERR)
    {
        LOG_ERR("Error occurred setting the SIGINT handler");
        return 6;
    }
    if (signal(SIGTERM, sig_handler) == SIG_ERR)
    {
        LOG_ERR("Error occurred setting the SIGTERM handler");
        return 6;
    }
    if (signal(SIGHUP, sig_handler) == SIG_ERR)
    {
        LOG_ERR("Error occurred setting the SIGHUP handler");
        return 6;
    }

    while (CONTINUE_PROCESSING)
    {
        ifctrl_iwget_interface_info(iface);
        
        memset(stapkt->stations, 0, sizeof(stapkt->stations));
        stapkt->station_count = ifctrl_iwget_stations(iface->ifname, stapkt->stations, DUPLES_MAX_STATIONS);
        
        // channel spec
        memcpy(&stapkt->chan_spec, &iface->channel, sizeof(struct uwifi_chan_spec));
        
        //trim packet for efficiency - only send stations polled
        dynamic_size = sizeof(struct duples_stations) - ((DUPLES_MAX_STATIONS - stapkt->station_count) * sizeof(struct sta_info));
        dhdr->pload_size = htons(dynamic_size);
        dynamic_size += sizeof(struct duples_header);

        if (sendto(outfd, (const void *)rspkt, dynamic_size, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) < 0)
        {
            LOG_ERR("Error sending station info.");
            break;
        }
        
        usleep(5000000);
    }

    /* cleanup and exit */
    LOG_INF("Cleaning up and shutting down");
    // ifctrl_finish(); // invalid pointer error?
    // uwifi_fini(iface);
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
