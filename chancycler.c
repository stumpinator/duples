//#include "duples.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include "uwifi/conf.h"
#include "uwifi/log.h"
#include "uwifi/ifctrl.h"
#include "uwifi/channel.h"

//log level
static int MYLL = LL_INFO;
//loop flag
static bool CONTINUE_PROCESSING = true;

struct chancycler_opts
{
    char *ifname;
    uint64_t interval;
    uint16_t loglevel;
    bool daemonize;
};

bool parseopts(int argc, char **argv, struct chancycler_opts *myopts)
{
    int opt = 0;
    float interval;

    memset(myopts, 0, sizeof(struct chancycler_opts));
    myopts->daemonize = false;
    myopts->loglevel = MYLL;
    myopts->interval = 2000000;

    while ((opt = getopt(argc, argv, ":i:t:l:s")) != -1)
    {
        switch(opt)
        {
            case 'i':
                myopts->ifname = optarg;
                break;
            case 't':
                if (sscanf(optarg, "%f", &interval) != 1)
                {
                    return false;
                }
                myopts->interval = interval * 1000000;
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
    struct chancycler_opts myopts;
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    int idx = 0;
    
    if (!parseopts(argc, argv, &myopts))
    {
        printf("example: %s -i wifi0 [-t 2.0] [-l 3] [-s]\n", argv[0]);
        printf("-i      interface to cycle channels. required\n");
        printf("-t      time interval in seconds between changing channels. default 2.0\n");
        printf("-l      log level 2(CRIT) - 7(DEBUG). default 3(ERROR). DEBUG requires compile flag\n");
        printf("-s      run as service (daemonize). currently not implemented\n");
        return 1;
    }

    MYLL = myopts.loglevel;
    strncpy(iface->ifname, myopts.ifname, IF_NAMESIZE);
    LOG_INF("Using interface %s", iface->ifname);

    if (!ifctrl_init())
    {
        LOG_ERR("Error during interface control initialization.");
        return 2;
    }
    
    if (!ifctrl_iwget_interface_info(iface))
    {
        LOG_ERR("Error getting interface info for %s", iface->ifname);
        return 3;
    }
    memcpy(&iface->channel_set, &iface->channel, sizeof(iface->channel));
    
    if (!uwifi_channel_init(iface))
    {
        LOG_ERR("Error initializing channel list for %s", iface->ifname);
        return 4;
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
    if (signal(SIGHUP, sig_handler) == SIG_ERR)
    {
        LOG_ERR("Error occurred setting the SIGHUP handler");
        return 6;
    }

    iface->channel_time = myopts.interval;
    while (CONTINUE_PROCESSING)
    {
        LOG_INF("Setting frequency to %i on %s.", iface->channels.chan[idx].freq, iface->ifname);
        if (!ifctrl_iwset_freq(iface->ifname, iface->channels.chan[idx].freq, CHAN_WIDTH_20, iface->channels.chan[idx].freq))
        {
            LOG_ERR("Error setting frequency to %i on %s.", iface->channels.chan[idx].freq, iface->ifname);
        }
        else
        {
            usleep(iface->channel_time);
        }
        idx++;
        if (idx >= iface->channels.num_channels || idx >= MAX_CHANNELS)
        {
            idx = 0;
        }
    }

    /* cleanup and exit */
    ifctrl_finish();
    free(iface);
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
