#include <sys/time.h>

#include "uwifi/channel.h"
#include "uwifi/ifctrl.h"

#ifndef _DUPLES_H_
#define _DUPLES_H_

#define DUPLES_PAYLOAD_RAW          0
#define DUPLES_PAYLOAD_UWIFI        1
#define DUPLES_PAYLOAD_STATIONS     2

#define DUPLES_MAX_STATIONS         64

struct duples_header
{
    unsigned char           hdr_version;    //version of this packet header
    unsigned char           hdr_size;       //total size of the header e.g. sizeof(struct duples_header)
    bool                    le_src;         //is payload little endian?
    unsigned char           pload_type;     //payload type
    uint16_t                pload_size;     //payload size e.g. sizeof(struct uwifi_packet);
    uint16_t                pad0;           //padding/reserved
};

struct duples_stations
{
    unsigned char           iface_mac[6];
    uint16_t                pad0;
    struct uwifi_chan_spec  chan_spec;
    uint32_t                station_count;
    struct sta_info         stations[DUPLES_MAX_STATIONS];
};

#endif
