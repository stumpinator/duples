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

//socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//log level
static int MYLL = LL_INFO;
//loop flag
static bool CONTINUE_PROCESSING = true;

struct udpinjopts
{
    char *ifname;
    struct in_addr daddr;
    uint16_t dport;
    uint16_t loglevel;
    bool daemonize;
};

bool parseopts(int argc, char **argv, struct udpinjopts *myopts)
{
    int opt = 0;
    int ll = 0;

    memset(myopts, 0, sizeof(struct udpinjopts));
    myopts->daemonize = false;
    myopts->loglevel = MYLL;
    //myopts->dport = 2400;

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

    if ((myopts->ifname == NULL) || (myopts->daddr.s_addr == 0) || (myopts->dport == 0))
    {
        return false;
    }
    return true;
}

static void sig_handler(int signumber)
{
    LOG_INF("Caught signal");
    CONTINUE_PROCESSING = false;
}

int main(int argc, char **argv) {
    struct udpinjopts myopts;
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    unsigned int buffsize = 4096; //size of buffer for packets
    unsigned char *buffr = calloc(1, buffsize); //packet buffer
    unsigned int total_size = 0; //sizeof(struct duples_header) + payload size
    struct duples_header *dhdr; // = (struct duples_header *)rspkt;
    int rsize = -1;
    int opt = 0;
    int sockfd = -1;
    struct sockaddr_in servaddr, clientaddr;
    struct iovec iov; //used for recvmsg
    struct msghdr message; //used for recvmsg
    struct timeval socket_timeout;
    
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    memset(&clientaddr, 0, sizeof(struct sockaddr_in));
    memset(&iov, 0, sizeof(iov));
    memset(&message, 0, sizeof(message));
    
    if (!parseopts(argc, argv, &myopts))
    {
        printf("example: %s -m mon0 -i 127.0.0.1 -p 2345 -l 2 -d\n", argv[0]);
        printf("-m      monitor interface to inject packets\n");
        printf("-i      IP to listen for UDP packets\n");
        printf("-p      port to listen for UDP packets\n");
        printf("-l      log level 2(CRIT) - 7(DEBUG).  default 6(INFO)\n");
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
        LOG_ERR("Couldn't open UDP socket.");
        return 5;
    }
    socket_timeout.tv_sec = 0;
    socket_timeout.tv_usec = 10000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&socket_timeout, sizeof(socket_timeout)) < 0)
    {
        LOG_ERR("Error setting socket timeout");
        return 5;
    }

    servaddr.sin_family = AF_INET;
    //servaddr.sin_addr.s_addr = inet_addr(argv[2]);
    servaddr.sin_addr = myopts.daddr;
    servaddr.sin_port = htons(myopts.dport);

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
        LOG_ERR("Error binding to %s:%i", inet_ntoa(myopts.daddr), myopts.dport);
        return 6;
    }

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

    while (CONTINUE_PROCESSING)
    {
        rsize = recvmsg(sockfd, &message, 0);
        if (rsize < 2) { 
            //LOG_INF("Received size (%i) too small to process header", rsize);
            continue; 
        }
    
        dhdr = (struct duples_header *)buffr;
        if (rsize < dhdr->hdr_size) { 
            LOG_INF("Received size smaller than expected header size (%i)", dhdr->hdr_size);
            continue; 
        }
        
        total_size = dhdr->hdr_size + ntohs(dhdr->pload_size);
        if (rsize < total_size) { 
            LOG_INF("Total size smaller than expected size (%i)", total_size);
            continue;
        }

        if (dhdr->pload_type != DUPLES_PAYLOAD_RTAP)
        {
            LOG_ERR("Received invalid payload type %i", dhdr->pload_type);
            continue;
        }

        rsize = send(iface->sock, buffr + dhdr->hdr_size, ntohs(dhdr->pload_size), MSG_DONTWAIT);
        if (rsize == -1)
        {
            LOG_ERR("Error occured sending message over interface %s", iface->ifname);
        }
        else
        {
            LOG_INF("Sent %i bytes", rsize);
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
