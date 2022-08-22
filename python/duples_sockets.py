import socket
import multiprocessing as mp
import signal
from functools import partial
from duples import *


class DuplesUDPReceiver:
    def __init__(self):
        self.childprocs = list()
        self.listen_sock = None
        self.server_address = None
        self.filter_function = None
        self.parser_function = None
        self._sig_handler = partial(self.signal_handler)
        self.log_queue = mp.Queue()
        self.log_queue.cancel_join_thread()
        self.initialized = False
        self.active = mp.Event()

    def initialize(self, ip, port, timeout=0.5, parsers=4, filter_function=None, parser_function=None):
        assert type(timeout) is float, f"Invalid timeout ({timeout}).  Must be float type."
        assert type(parsers) is int, f"Invalid parsers ({parsers}).  Must be int type."
        assert parsers > 0, "Parsers must be at least 1."
        if filter_function is None:
            self.filter_function = lambda x: True
        else:
            self.filter_function = filter_function

        if parser_function is None:
            self.parser_function = self.packet_thread
        else:
            self.parser_function = parser_function

        assert callable(self.filter_function), "pktfilter must be a callable function."
        assert callable(self.parser_function), "pktthread must be a callable function."
        assert not self.active.is_set(), "This class is currently active."

        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.listen_sock.bind(self.server_address)
        self.listen_sock.settimeout(timeout)

        self.childprocs.clear()
        for i in range(0, parsers):
            pktp = mp.Process(target=parser_function, args=(self.listen_sock, self.filter_function))
            pktp.daemon = True
            self.childprocs.append(pktp)
        
        self.initialized = True

    def signal_handler(self, signal, frame):
        self.active.clear()

    def start(self):
        assert self.initialized, "Receiver is not initialized."
        assert not self.active.is_set(), "This class is currently active"
        self.active.set()
        for p in self.childprocs:
            p.start()

    def stop(self):
        self.active.clear()
        
        for p in self.childprocs:
            if p.is_alive():
                p.terminate()
    
        for p in self.childprocs:
            p.join()

        if self.listen_sock:
            self.listen_sock.close()
        
        self.childprocs.clear()
        self.initialized = False

    def run(self):
        self.start()
        original_signal = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        while self.active.is_set():
            try:
                parsed = self.log_queue.get(block=True,timeout=0.5)
            except:
                continue
            if type(parsed) == UwifiPacket:
                print(f"TA: {parsed.TA()} RA: {parsed.RA()} BSSID: {parsed.BSSID()} SIG: {parsed.phy_signal} FREQ: {parsed.phy_freq} SSID: {parsed.SSID()}")
            else:
                print("Got stations?")
        self.stop()
        signal.signal(signal.SIGINT, original_signal)        

    def packet_thread(self, sock, packet_filter):
        while self.active.is_set():
            try:
                data, ancdata, msg_flags, address = sock.recvmsg(4096)
            except:
                continue

            try:        
                header = DuplesHeader(data)
                if header.PLOAD_TYPE == defs.DUPLES_PAYLOAD_UWIFI:
                    packet = UwifiPacket(header.LE_SRC, header.PLOAD_TYPE, header.PLOAD_SIZE, data[header.HDR_SIZE:])
                elif header.PLOAD_TYPE == defs.DUPLES_PAYLOAD_STATIONS:
                    continue
                else:
                    continue
            except Exception as e:
                print(f"Exception occured parsing packet: {str(e)}")
                continue
            
            if not packet_filter(packet):
                continue
            
            try:
                self.log_queue.put_nowait(packet)
            except:
                pass

        self.log_queue.cancel_join_thread()
        self.log_queue.close()


class DuplesUDPSender:
    DEF_RTAP = b'\x00\x00\x08\x00\x00\x00\x00\x00'
    def __init__(self, ip, port):
        self.dest_ip = ip
        self.dest_port = port
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.header = DuplesHeader()
    
    def send(self, data, addradiotap=False, ptype=defs.DUPLES_PAYLOAD_RTAP):
        assert type(ptype) is int, f"Invalid packet type ({ptype}).  Must be int type."
        if addradiotap:
            pload = self.DEF_RTAP + bytes(data)
        else:
            pload = bytes(data)
        self.header.PLOAD_SIZE = len(pload)
        self.header.PLOAD_TYPE = ptype
        packet = self.header.pack() + pload
        self.send_socket.sendto(packet, (self.dest_ip, self.dest_port))


if __name__ == "__main__":
    pass
