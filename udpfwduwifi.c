#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

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
static int MYLL = LL_ERR;
//loop flag
static bool CONTINUE_PROCESSING = true;

struct udpfwdopts
{
    char *ifname;
    struct in_addr daddr;
    uint16_t dport;
    uint16_t loglevel;
    bool daemonize;
};

bool parseopts(int argc, char **argv, struct udpfwdopts *myopts)
{
    int opt = 0;
    
    memset(myopts, 0, sizeof(struct udpfwdopts));
    myopts->daemonize = false;
    myopts->loglevel = MYLL;
    myopts->dport = 2412;
    inet_aton("127.0.0.1", &myopts->daddr);

    while ((opt = getopt(argc, argv, ":m:i:p:l:d")) != -1)
    {
        switch(opt)
        {
            case 'm':
                myopts->ifname = optarg;
                break;
            case 'i':
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
            case 'd':
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

    //if ((myopts->ifname == NULL) || (myopts->daddr.s_addr == 0) || (myopts->dport == 0))
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
    struct udpfwdopts myopts;
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    unsigned int buffsize = 4096; //size of buffer for packets
    unsigned char *buffr = calloc(1, buffsize); //packet buffer
    unsigned int total_size = sizeof(struct duples_header) + sizeof(struct uwifi_packet);
    unsigned char *rspkt = calloc(1, total_size);
    struct duples_header *rhdr = (struct duples_header *)rspkt;
    struct uwifi_packet *upkt = (struct uwifi_packet *)(rspkt + sizeof(struct duples_header));
    int rsize = -1;
    int outfd = -1;
    struct sockaddr_in destaddr;
    struct timeval socket_timeout;

    if (!parseopts(argc, argv, &myopts))
    {
        printf("example: %s -m mon0 -i 127.0.0.1 -p 2345 -l 2 -d\n", argv[0]);
        printf("-m      monitor interface to sniff packets. required\n");
        printf("-i      IP to send UDP packets. default 127.0.0.1\n");
        printf("-p      port to send UDP packets. default 2412\n");
        printf("-l      log level 2(CRIT) - 7(DEBUG).  default 3(ERROR)\n");
        printf("-d      daemonize.  default false.  currently not implemented\n");
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
    //set timeout on the monitor socket
    socket_timeout.tv_sec = 0;
    socket_timeout.tv_usec = 10000;
    if (setsockopt(iface->sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&socket_timeout, sizeof(socket_timeout)) < 0)
    {
        LOG_ERR("Error setting socket timeout");
        return 4;
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
    rhdr->hdr_version = 1;
    rhdr->hdr_size = sizeof(struct duples_header);
    rhdr->le_src = (__BYTE_ORDER == __LITTLE_ENDIAN);
    rhdr->pload_type = DUPLES_PAYLOAD_UWIFI;
    rhdr->pload_size = htons(sizeof(struct uwifi_packet));

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
        rsize = recv(iface->sock, buffr, buffsize, 0);
        if (rsize <= 0)
        {
            continue;
        }
            
        memset(upkt, 0, sizeof(struct uwifi_packet));
        rsize = uwifi_parse_raw(buffr, rsize, upkt, iface->arphdr);
        if (rsize < 0)
        {
            LOG_DBG("Error parsing with uwifi.");
            continue;
        }
        
        if (sendto(outfd, (const void *)rspkt, total_size, 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) < 0)
        {
            LOG_ERR("Error forwarding packet metadata.  Shutting down.");
            break;
        }
        
    }

    /* cleanup and exit */
    LOG_INF("Cleaning up and shutting down");
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
    va_list args;
    if (MYLL >= ll)
    {
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
