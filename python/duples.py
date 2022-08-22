import struct
import binascii
from duples_structs import DuplesStructs as structs
from duples_defs import DuplesDefs as defs


MAC_FORMAT = "%02x:%02x:%02x:%02x:%02x:%02x"


def bytes_to_mac(mac: bytes):
    return MAC_FORMAT % structs.macaddr.unpack(mac)

def mac_to_bytes(mac: str):
    binascii.unhexlify(mac.replace(':',''))


class DuplesHeader:
    hdr_version: int = 1
    hdr_size: int = 16
    le_src: bool = False
    pload_type: int = 0
    pload_size: int = 0
    def __init__(self, data=None):
        if data is not None:
            self.unpack(data)

    def unpack(self, data):
        if len(data) < 2:
            raise Exception(f"Expected data is too small.")
        
        hver = data[0]
        hsz = data[1]
        hdrstruct = structs.duples_header.get((hver,hsz),None)

        if hdrstruct is None:
            raise Exception(f"Invalid header or uknown header type. Header version {hver} size {hsz}")

        self.hdr_version, self.hdr_size, self.le_src, self.pload_type, self.pload_size = hdrstruct.unpack_from(data)
    
    def pack(self) -> bytes:
        hdrstruct = structs.duples_header.get((self.hdr_version,self.hdr_size),None)

        if hdrstruct is None:
            raise Exception(f"Invalid header or uknown header type. Header version {self.hdr_version} size {self.hdr_size}")

        return hdrstruct.pack(self.hdr_version, self.hdr_size, self.le_src, self.pload_type, self.pload_size)
    
    def to_dict(self) -> dict:
        return dict(hdr_version=self.hdr_version,
                    hdr_size=self.hdr_size,
                    le_src=self.le_src,
                    pload_type=self.pload_type,
                    pload_size=self.pload_size)


class StationInfo:
    mac: bytes
    rssi: int
    rssi_avg: int
    last: int
    _sta_info: struct.Struct
    _le: bool

    def __init__(self, little_endian=True, data=None):
        self.mac = None
        self.rssi = None
        self.rssi_avg = None
        self.last = None
        self._le = little_endian

        self._sta_info = structs.sta_info.get(self._le, None)
        if self._sta_info is None:
            raise Exception(f"Invalid little endian flag: {self._le}")

        if data is not None:
            self.unpack(data)

    def packed_size(self):
        return self._sta_info.size

    def unpack(self, data):
        self.mac, self.rssi, self.rssi_avg, self.last = self._sta_info.unpack(data)

    def unpack_from(self, data, offset: int=0):
        self.mac, self.rssi, self.rssi_avg, self.last = self._sta_info.unpack_from(data, offset)

    def pack(self) -> bytes:
        return self._sta_info.pack(self.mac, self.rssi, self.rssi_avg, self.last)

    def to_dict(self) -> dict:
        return dict(mac=bytes_to_mac(self.mac),
                    rssi=self.rssi,
                    rssi_avg=self.rssi_avg,
                    last=self.last)


class StationsPacket:
    mac: bytes = None
    freq: int = 0
    width: int = 0
    center: int = 0
    station_count: int = 0
    stations: list = list()
    _duples_stations: struct.Struct
    _le: bool
    
    def __init__(self, little_endian: bool=True, data=None):
        self._le = little_endian

        self._duples_stations = structs.duples_stations.get(self._le, None)
        if self._duples_stations is None:
            raise Exception(f"Invalid little endian flag: {self._le}")
        
        if data is not None:
            self.unpack_from(data)

    def packed_size(self):
        sta_inf = structs.sta_info.get(self._le)
        return self._duples_stations.size + (self.station_count * sta_inf.size)

    def unpack_from(self, data, offset: int=0):
        self.mac, self.freq, self.width, self.center, self.station_count = self._duples_stations.unpack_from(data, offset)
        if self.station_count <= 0:
            return
        
        offset = self._duples_stations.size
        while (offset < len(data)):
            si = StationInfo(self._le)
            si.unpack_from(data, offset)
            self.stations.append(si)
            offset += si.packed_size()

        if len(self.stations) != self.station_count:
            raise Exception(f"Expected station count {self.station_count} does not equal parsed count {len(self.stations)}")
    
    def to_dict(self):
        return dict(mac=bytes_to_mac(self.mac),
                    freq=self.freq,
                    width=defs.UWIFI_CHAN_WIDTHS.get(self.width, "UNKNOWN"),
                    center=self.center,
                    station_count=self.station_count,
                    stations=list(x.to_dict() for x in self.stations))


class UwifiPacket:
    _le: bool
    def __init__(self, little_endian: bool, payload_size, data=None):
        self._SSID = None
        self._TA_MACADDR = None
        self._RA_MACADDR = None
        self._BSSID_MACADDR = None
        self._FC_TYPE = None
        self._FC_STYPE = None
        self._le = little_endian
        if data is not None:
            self.unpack(payload_size, data)
    
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
        return MAC_FORMAT % structs.macaddr.unpack(macdata)

    def TYPE_ENUM(self):
        if self._FC_TYPE is None:
            fc = self.__dict__.get('wlan_type', None)
            if fc is not None:
                self._FC_TYPE = (fc & defs.WLAN_FRAME_FC_TYPE_MASK) >> 2
        return self._FC_TYPE

    def TYPE(self):
        t = self.TYPE_ENUM()
        if t is not None:
            t = defs.WLAN_FRAME_TYPES.get(t, None)
        return t
        
    def SUBTYPE_ENUM(self):
        if self._FC_STYPE is None:
            fc = self.__dict__.get('wlan_type', None)
            if fc is not None:
                self._FC_STYPE = (fc & defs.WLAN_FRAME_FC_STYPE_MASK) >> 4
        return self._FC_STYPE

    def SUBTYPE(self):
        st = self.SUBTYPE_ENUM()
        if st is not None:
            t = self.TYPE_ENUM()
            if t is not None:
                if t == defs.WLAN_FRAME_TYPES["MGMT"]: 
                    st = defs.WLAN_FRAME_TYPES_MGMT.get(st, "RESERVED")
                elif t == defs.WLAN_FRAME_TYPES["CTRL"]:
                    st = defs.WLAN_FRAME_TYPES_CTRL.get(st, "RESERVED")
                elif t == defs.WLAN_FRAME_TYPES["DATA"]:
                    st = defs.WLAN_FRAME_TYPES_DATA.get(st, "RESERVED")
                elif t == defs.WLAN_FRAME_TYPES["EXTE"]:
                    st = defs.WLAN_FRAME_TYPES_EXTE.get(st, "UNKNOWN")
        return st

    def unpack(self, payload_size, data):
        if len(data) < payload_size:
            raise Exception(f"Expected data is too small.  Expected >= {payload_size} Received {len(data)}")
        
        uwstruct = structs.uwifi_pkt.get((self._le, payload_size), None)
        if uwstruct is None:
            raise Exception(f"Error: no struct definition for endian/size combination {self._le}/{payload_size}")

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
        return self.FLAGWITHBITS(flag, 'wlan_flags', defs.WLAN_FLAGS_BITS)
        
    def PHYFLAG(self, flag):
        return self.FLAGWITHBITS(flag, 'phy_flags', defs.PHY_FLAGS_BITS)
            
    def WLANMODE(self, flag):
        return self.FLAGWITHBITS(flag, 'wlan_mode', defs.WLAN_MODE_BITS)
        

if __name__ == "__main__":
    pass
