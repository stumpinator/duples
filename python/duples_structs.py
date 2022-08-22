import struct


class DuplesStructs(object):
    """
    structs used for packing/unpacking low level data, translated from C headers
    """
    
    # header structs indexed by version and size
    # should always be network byte order (big-endian)
    duples_header = { (1,8):struct.Struct("!bb?bHxx") }

    duples_stations = { True:struct.Struct('<6sxxIiII'), False:struct.Struct('>6sxxIiII') }
    
    # macaddr_format = "%02x:%02x:%02x:%02x:%02x:%02x"
    macaddr = struct.Struct("BBBBBB")

    uwifi_pkt = { (True, 168):struct.Struct("<IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii"), \
                        (False, 168):struct.Struct(">IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii") }

    uwifi_chan_freq = { True:struct.Struct("<iIibbxx"), False:struct.Struct(">iIibbxx") }
    uwifi_chan_spec = { True:struct.Struct("<IiI"), False:struct.Struct(">IiI") }

    # ifctrl.h
    sta_info = { True:struct.Struct("<6sbbI"), False:struct.Struct(">6sbbI") }
