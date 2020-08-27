//#include "duples.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <conf.h>
#include <raw_parser.h>
#include <log.h>
#include <packet_sock.h>
#include <netdev.h>
//#include <radiotap.h>
#include <ifctrl.h>
#include <channel.h>

static int MYLL = LL_INFO;

int main(int argc, char **argv) {
    struct uwifi_interface *iface = calloc(1, sizeof(struct uwifi_interface));
    int idx = 0;
    if (argc < 2)
    {
        LOG_ERR("usage: %s <iface>", argv[0]);
        return 1;
    }

    strncpy(iface->ifname, argv[1], IF_NAMESIZE);
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

    iface->channel_time = 2000000;
    while (true)
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
