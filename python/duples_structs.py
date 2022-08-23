from struct import Struct


class DuplesStructs(object):
    """
    structs used for packing/unpacking low level data, translated from C headers
    """
    
    # header structs indexed by version and size
    # should always be network byte order (big-endian)
    duples_header = { (1,8):Struct("!bb?bHxx") }

    duples_stations = { True:Struct('<6sxxIiII'), False:Struct('>6sxxIiII') }
    
    macaddr = Struct("BBBBBB")

    uwifi_pkt = { True:Struct("<IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii"), \
                False:Struct(">IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii") }

    uwifi_chan_freq = { True:Struct("<iIibbxx"), False:Struct(">iIibbxx") }
    uwifi_chan_spec = { True:Struct("<IiI"), False:Struct(">IiI") }

    # ifctrl.h
    sta_info = { True:Struct("<6sbbI"), False:Struct(">6sbbI") }
