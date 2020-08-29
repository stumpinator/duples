#include <sys/time.h>

#ifndef _DUPLES_H_
#define _DUPLES_H_

#define DUPLES_PAYLOAD_RAW     0
#define DUPLES_PAYLOAD_UWIFI   1

struct duples_header
{
    unsigned char           hdr_version;    //version of this packet header
    unsigned char           hdr_size;       //total size of the header e.g. sizeof(struct duples_header)
    bool                    le_src;         //is data little endian?
    unsigned char           pload_type;     //payload type
    uint16_t                pload_size;     //payload size e.g. sizeof(struct uwifi_packet);
    uint16_t                pad0;           //padding/reserved
    struct timeval          cap_ts;         //timestamp of capture e.g. pcap's timestamp
};

#endif