class DuplesDefs(object):
    """
    Constants, #defs, and enums
    """
    DUPLES_PAYLOAD_RAW = 0
    DUPLES_PAYLOAD_UWIFI = 1
    DUPLES_PAYLOAD_RTAP = 2
    DUPLES_PAYLOAD_STATIONS = 3

    DUPLES_MAX_STATIONS = 32

    UWIFI_CHAN_WIDTHS = { "CHAN_WIDTH_UNSPEC":0,0:"CHAN_WIDTH_UNSPEC", 
                            "CHAN_WIDTH_20_NOHT":1,1:"CHAN_WIDTH_20_NOHT", 
                            "CHAN_WIDTH_20":2,2:"CHAN_WIDTH_20", 
                            "CHAN_WIDTH_40":3,3:"CHAN_WIDTH_40", 
                            "CHAN_WIDTH_80":4,4:"CHAN_WIDTH_80", 
                            "CHAN_WIDTH_160":5,5:"CHAN_WIDTH_160", 
                            "CHAN_WIDTH_8080":6,6:"CHAN_WIDTH_8080" }

    WLAN_FRAME_FC_TYPE_MASK = 0x0C
    WLAN_FRAME_FC_STYPE_MASK = 0xF0
    WLAN_FRAME_FC_MASK = WLAN_FRAME_FC_TYPE_MASK | WLAN_FRAME_FC_STYPE_MASK
    WLAN_FRAME_TYPES = { "MGMT":0,0:"MGMT", "CTRL":1,1:"CTRL", "DATA":2,2:"DATA", "EXTE":3,3:"EXTE" }
    WLAN_FRAME_TYPES_MGMT = {"ASSOC_REQ":0,0:"ASSOC_REQ", "ASSOC_RESP":1,1:"ASSOC_RESP",\
                            "REASSOC_REQ":2,2:"REASSOC_REQ", "REASSOC_RESP":3,3:"REASSOC_RESP",\
                            "PROBE_REQ":4,4:"PROBE_REQ", "PROBE_RESP":5,5:"PROBE_RESP", "TIMING":6,6:"TIMING",\
                            "BEACON":8,8:"BEACON", "ATIM":9,9:"ATIM", "DISASSOC":10,10:"DISASSOC", "AUTH":11,11:"AUTH",\
                            "DEAUTH":12,12:"DEAUTH", "ACTION":13, 13:"ACTION", "ACTION_NOACK":14, 14:"ACTION_NOACK"}
    WLAN_FRAME_TYPES_CTRL = {"BEAM_REP":4,4:"BEAM_REP", "VHT_NDP":5,5:"VHT_NDP", "CTRL_EXT":6,6:"CTRL_EXT", \
                            "CTRL_WRAP":7,7:"CTRL_WRAP", "BLKACK_REQ":8,8:"BLKACK_REQ", "BLKACK":9,9:"BLKACK", \
                            "PSPOLL":10,10:"PSPOLL", "RTS":11,11:"RTS", "CTS":12,12:"CTS", "ACK":13,13:"ACK", \
                            "CF_END":14,14:"CF_END", "CF_END_ACK":15,15:"CF_END_ACK"}
    WLAN_FRAME_TYPES_DATA = {"DATA":0,0:"DATA", "DATA_CF_ACK":1,1:"DATA_CF_ACK", "DATA_CF_POLL":2,2:"DATA_CF_POLL",\
                            "DATA_CF_ACKPOLL":3,3:"DATA_CF_ACKPOLL", "NULL":4,4:"NULL", "CF_ACK":5,5:"CF_ACK",\
                            "CF_POLL":6,6:"CF_POLL", "CF_ACKPOLL":7,7:"CF_ACKPOLL", "QDATA":8,8:"QDATA",\
                            "QDATA_CF_ACK":9,9:"QDATA_CF_ACK", "QDATA_CF_POLL":10,10:"QDATA_CF_POLL",\
                            "QDATA_CF_ACKPOLL":11,11:"QDATA_CF_ACKPOLL", "QOS_NULL":12,12:"QOS_NULL",\
                            "QOS_CF_POLL":14,14:"QOS_CF_POLL", "QOS_CF_ACKPOLL":15,15:"QOS_CF_ACKPOLL"}
    WLAN_FRAME_TYPES_EXTE = { } #"DMG_BEACON":0,0:"DMG_BEACON"}
    WLAN_FLAGS_BITS = {"wep":0,0:"wep", "retry":1,1:"retry", "wpa":2,2:"wpa", "rsn":3,3:"rsn", "ht40plus":4,4:"ht40plus"}
    PHY_FLAGS_BITS = {"shortpre":0,0:"shortpre", "badfcs":1,1:"badfcs", "a":2,2:"a", "b":3,3:"b", "g":4,4:"g"}
    WLAN_MODE_BITS = {"AP":0,0:"AP", "IBSS":1,1:"IBSS", "STA":2,2:"STA", "PROBE":3,3:"PROBE", "4ADDR":4,4:"4ADDR",\
                    "UNKNOWN":5,5:"UNKNOWN"}
