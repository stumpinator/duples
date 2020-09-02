import socket
import sys
import struct

import multiprocessing as mp
import signal

def duples_packet_thread(sock, logq, active, pktfilter):
    while active.is_set():
        try:
            data, ancdata, msg_flags, address = sock.recvmsg(4096)
        except:
            continue

        try:        
            rshdr = DuplesHeader(data)
            if rshdr.PLOAD_TYPE == DuplesHeader.DUPLES_PAYLOAD_UWIFI:
                rspkt = UwifiPacket(rshdr.LE_SRC, rshdr.PLOAD_TYPE, rshdr.PLOAD_SIZE, data[rshdr.HDR_SIZE:])
            else:
                continue
        except Exception as e:
            print(f"Exception occured parsing packet: {str(e)}")
            continue
        
        if not pktfilter(rspkt):
            continue
        
        try:
            logq.put_nowait(rspkt)
        except:
            pass

    logq.cancel_join_thread()
    logq.close()

class DuplesHeader:
    hdr_structs = { (1,16):struct.Struct(">bb?bHxxLL"), \
                    (1,24):struct.Struct(">bb?bHxxQQ") } #header structs indexed by version and size
    DUPLES_PAYLOAD_RAW = 0
    DUPLES_PAYLOAD_UWIFI = 1
    def __init__(self, data=None):
        self.HDR_VER = None
        self.HDR_SIZE = None
        self.LE_SRC = None
        self.PLOAD_TYPE = None
        self.PLOAD_SIZE = None
        self.TV_SEC = None
        self.TV_USEC = None
        if data is not None:
            self.parsedata(data)

    def parsedata(self, data):
        if len(data) < 2:
            raise Exception(f"Expected data is too small.")
        
        hver = data[0]
        hsz = data[1]
        hdrstruct = self.hdr_structs.get((hver,hsz),None)

        if hdrstruct is None:
            raise Exception(f"Invalid header or uknown header type. Header version {hver} size {hsz}")

        if len(data) < hsz:
            raise Exception(f"Expected header is too small.  Expected >= {self.HDR_SIZE} Received {len(data)}")
        
        self.HDR_VER, self.HDR_SIZE, self.LE_SRC, self.PLOAD_TYPE, self.PLOAD_SIZE, self.TV_SEC, self.TV_USEC = hdrstruct.unpack_from(data)
    
    def setvalues(self, hdr_ver=1, hdr_size=16, le=False, ptype=0, psize=0, tvsec=0, tvusec=0):
        self.HDR_VER = hdr_ver
        self.HDR_SIZE = hdr_size
        self.LE_SRC = le
        self.PLOAD_TYPE = ptype
        self.PLOAD_SIZE = psize
        self.TV_SEC = tvsec
        self.TV_USEC = tvusec
        
    def build(self):
        hdrstruct = self.hdr_structs.get((self.HDR_VER,self.HDR_SIZE),None)

        if hdrstruct is None:
            raise Exception(f"Invalid header or uknown header type. Header version {self.HDR_VER} size {self.HDR_SIZE}")

        return hdrstruct.pack(self.HDR_VER, self.HDR_SIZE, self.LE_SRC, self.PLOAD_TYPE, self.PLOAD_SIZE, self.TV_SEC, self.TV_USEC)


class UwifiPacket:
    uwifi_structs = { (True, 1, 168):struct.Struct("<IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii"), \
                    (False, 1, 168):struct.Struct(">IiIBBxxII?xxxI??H6s6s6s34sQIIBxxxiBBBxIIIBBBxIIIIIIIii") }
    macaddr_struct = struct.Struct("BBBBBB")
    macaddr_format = "%02x:%02x:%02x:%02x:%02x:%02x"
    
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

    def __init__(self, little_endian, payload_type, payload_size, data=None):
        self._SSID = None
        self._TA_MACADDR = None
        self._RA_MACADDR = None
        self._BSSID_MACADDR = None
        self._FC_TYPE = None
        self._FC_STYPE = None
        if data is not None:
            self.parsedata(little_endian, payload_type, payload_size, data)
    
    def TA(self):
        if self._TA_MACADDR is None:
            mdat = self.__dict__.get('wlan_ta', None)
            if mdat is not None:
                self._TA_MACADDR = self.format_mac(mdat)
        return self._TA_MACADDR
    
    def RA(self):
        if self._RA_MACADDR is None:
            mdat = self.__dict__.get('wlan_ra', None)
            if mdat is not None:
                self._RA_MACADDR = self.format_mac(mdat)
        return self._RA_MACADDR

    def BSSID(self):
        if self._BSSID_MACADDR is None:
            mdat = self.__dict__.get('wlan_bssid', None)
            if mdat is not None:
                self._BSSID_MACADDR = self.format_mac(mdat)
        return self._BSSID_MACADDR

    def ESSID(self):
        if self._SSID is None:
            mdat = self.__dict__.get('wlan_essid', None)
            if mdat is not None:
                self._SSID = self.wlan_essid.decode(encoding='utf-8').strip()
        return self._SSID
    
    def SSID(self):
        return self.ESSID()

    def format_mac(self, macdata):
        return self.macaddr_format % self.macaddr_struct.unpack(macdata)

    def TYPE_ENUM(self):
        if self._FC_TYPE is None:
            fc = self.__dict__.get('wlan_type', None)
            if fc is not None:
                self._FC_TYPE = (fc & self.WLAN_FRAME_FC_TYPE_MASK) >> 2
        return self._FC_TYPE

    def TYPE(self):
        t = self.TYPE_ENUM()
        if t is not None:
            t = self.WLAN_FRAME_TYPES.get(t, None)
        return t
        
    def SUBTYPE_ENUM(self):
        if self._FC_STYPE is None:
            fc = self.__dict__.get('wlan_type', None)
            if fc is not None:
                self._FC_STYPE = (fc & self.WLAN_FRAME_FC_STYPE_MASK) >> 4
        return self._FC_STYPE

    def SUBTYPE(self):
        st = self.SUBTYPE_ENUM()
        if st is not None:
            t = self.TYPE_ENUM()
            if t is not None:
                if t == self.WLAN_FRAME_TYPES["MGMT"]: 
                    st = self.WLAN_FRAME_TYPES_MGMT.get(st, "RESERVED")
                elif t == self.WLAN_FRAME_TYPES["CTRL"]:
                    st = self.WLAN_FRAME_TYPES_CTRL.get(st, "RESERVED")
                elif t == self.WLAN_FRAME_TYPES["DATA"]:
                    st = self.WLAN_FRAME_TYPES_DATA.get(st, "RESERVED")
                elif t == self.WLAN_FRAME_TYPES["EXTE"]:
                    st = self.WLAN_FRAME_TYPES_EXTE.get(st, "UNKNOWN")
        return st

    def parsedata(self, little_endian, payload_type, payload_size, data):
        if len(data) < payload_size:
            raise Exception(f"Expected data is too small.  Expected >= {payload_size} Received {len(data)}")
        
        uwstruct = self.uwifi_structs.get((little_endian, payload_type, payload_size), None)
        if uwstruct is None:
            raise Exception(f"Error: no struct definition for endian/version/size combination {little_endian}/{payload_type}/{payload_size}")

        self.pkt_types, self.phy_signal, self.phy_rate, self.phy_rate_idx, self.phy_rate_flags, self.phy_freq, \
        self.phy_flags, self.phy_injected, self.wlan_len, self.wlan_fromds, self.wlan_tods, self.wlan_type, \
        self.wlan_ta, self.wlan_ra, self.wlan_bssid, self.wlan_essid, self.wlan_tsf, self.wlan_bintval, self.wlan_mode, \
        self.wlan_channel, self.wlan_chan_width, self.wlan_tx_streams, self.wlan_rx_streams, self.wlan_qos_class, \
        self.wlan_nav, self.wlan_seqno, self.wlan_flags, self.bat_version, self.bat_packet_type, self.bat_gw, \
        self.ip_src, self.ip_dst, self.tcpudp_port, self.olsr_type, self.olsr_neigh, self.olsr_tc, self.pkt_duration, \
        self.pkt_chan_idx, self.wlan_retries = uwstruct.unpack_from(data)

    def FLAGWITHBITS(self, flag, flagfield, flagbits):
        ff = self.__dict__.get(flagfield, None)
        fe = flagbits.get(flag, None)
        if ((ff is None) or (fe is None) or (not isinstance(fe, int))):
            return None
        return (ff >> fe) & 1

    def WLANFLAG(self, flag):
        return self.FLAGWITHBITS(flag, 'wlan_flags', self.WLAN_FLAGS_BITS)
        
    def PHYFLAG(self, flag):
        return self.FLAGWITHBITS(flag, 'phy_flags', self.PHY_FLAGS_BITS)
            
    def WLANMODE(self, flag):
        return self.FLAGWITHBITS(flag, 'wlan_mode', self.WLAN_MODE_BITS)
        
class DuplesUDPReceiver:
    def __init__(self):
        self.childprocs = list()
        self.listen_sock = None
        self.server_address = None
        self.filterfunc = None
        self.log_queue = mp.Queue()
        self.log_queue.cancel_join_thread()
        self.initialized = False
        self.active = mp.Event()

    def initialize(self, ip, port, timeout=0.5, parsers=4, pktfilter=None, pktthread=duples_packet_thread):
        assert type(timeout) is float, f"Invalid timeout ({timeout}).  Must be float type."
        assert type(parsers) is int, f"Invalid parsers ({parsers}).  Must be int type."
        assert parsers > 0, "Parsers must be at least 1."
        if pktfilter is None:
            self.filterfunc = lambda x: True
        else:
            self.filterfunc = pktfilter
        assert callable(self.filterfunc), "pktfilter must be a callable function."
        assert callable(pktthread), "pktthread must be a callable function."
        assert not self.active.is_set(), "This class is currently active."

        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.listen_sock.bind(self.server_address)
        self.listen_sock.settimeout(timeout)

        self.childprocs.clear()
        for i in range(0, parsers):
            pktp = mp.Process(target=pktthread, args=(self.listen_sock, self.log_queue, self.active, self.filterfunc))
            pktp.daemon = True
            self.childprocs.append(pktp)
        
        self.initialized = True

    def startprocessing(self):
        assert self.initialized, "Receiver is not initialized."
        assert not self.active.is_set(), "This class is currently active"
        self.active.set()
        for p in self.childprocs:
            p.start()

    def stopprocessing(self):
        self.active.clear()
        
        #print("Shutting down subproccesses")
        for p in self.childprocs:
            if p.is_alive():
                p.terminate()
    
        #print("Joining subprocesses")
        for p in self.childprocs:
            p.join()

        self.listen_sock.close()
        self.childprocs.clear()
        self.initialized = False

if __name__ == "__main__":
    pass
