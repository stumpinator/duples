import signal
from socket import socket, AF_INET, SOCK_DGRAM
from multiprocessing import Queue, Process, Event
from functools import partial
from duples import UwifiPacket, DuplesHeader, StationsPacket
from duples_defs import DuplesDefs as defs


class DuplesUDPReceiver:
    child_processes: list = list()
    parsed_queue: Queue = Queue()
    initialized: bool = False
    active: Event = Event()
    listen_sock: socket = None
    server_address: tuple = None
    filter_function = None
    parser_thread = None

    def __init__(self):
        self.parsed_queue.cancel_join_thread()

    def initialize(self, ip, port, timeout=0.5, parsers=4, filter_function=None, parser_thread=None):
        assert type(timeout) is float, f"Invalid timeout ({timeout}).  Must be float type."
        assert type(parsers) is int, f"Invalid parsers ({parsers}).  Must be int type."
        assert parsers > 0, "Parsers must be at least 1."
        assert not self.active.is_set(), "This class is currently active."

        if filter_function is None:
            self.filter_function = lambda x: True
        else:
            self.filter_function = filter_function

        if parser_thread is None:
            self.parser_thread = self.packet_thread
        else:
            self.parser_thread = parser_thread

        assert callable(self.filter_function), "pktfilter must be a callable function."
        assert callable(self.parser_thread), "pktthread must be a callable function."

        self.listen_sock = socket(AF_INET, SOCK_DGRAM)
        self.server_address = (ip, port)
        self.listen_sock.bind(self.server_address)
        self.listen_sock.settimeout(timeout)

        self.child_processes.clear()
        for i in range(0, parsers):
            pktp = Process(target=self.parser_thread, args=(self.listen_sock, self.filter_function))
            pktp.daemon = True
            self.child_processes.append(pktp)
        
        self.initialized = True

    def signal_handler(self, signal, frame):
        self.active.clear()

    def start(self):
        assert self.initialized, "Receiver is not initialized."
        assert not self.active.is_set(), "This class is currently active"
        self.active.set()
        for p in self.child_processes:
            p.start()

    def stop(self):
        self.active.clear()
        
        for p in self.child_processes:
            if p.is_alive():
                p.terminate()
    
        for p in self.child_processes:
            p.join()

        if self.listen_sock:
            self.listen_sock.close()
        
        self.child_processes.clear()
        self.initialized = False

    def run(self):
        self.start()
        original_signal = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, partial(self.signal_handler))
        
        while self.active.is_set():
            try:
                pload_type, parsed = self.parsed_queue.get(block=True, timeout=0.5)
            except:
                continue
            
            if pload_type == defs.DUPLES_PAYLOAD_UWIFI:
                print(f"TA: {parsed.TA()} RA: {parsed.RA()} BSSID: {parsed.BSSID()} SIG: {parsed.phy_signal} FREQ: {parsed.phy_freq} SSID: {parsed.SSID()}")
            elif pload_type == defs.DUPLES_PAYLOAD_STATIONS:
                print(parsed.to_dict())

        self.stop()
        signal.signal(signal.SIGINT, original_signal)        

    @staticmethod
    def packet_parser(data) -> tuple:
        header = DuplesHeader(data)
        if header.pload_type == defs.DUPLES_PAYLOAD_UWIFI:
            packet = UwifiPacket(header.le_src)
        elif header.pload_type == defs.DUPLES_PAYLOAD_STATIONS:
            packet = StationsPacket(header.le_src)
        else:
            return (None, None)
        packet.unpack_from(data, header.hdr_size)
        return (header.pload_type, packet)

    def packet_thread(self, sock, packet_filter):
        while self.active.is_set():
            try:
                data, ancdata, msg_flags, address = sock.recvmsg(4096)
            except:
                continue

            try:
                pload_type, parsed = self.packet_parser(data)
            except Exception as e:
                print(f"Exception occured parsing packet: {str(e)}")
                continue
            
            if pload_type is None:
                continue

            if not packet_filter(parsed):
                continue
            
            try:
                self.parsed_queue.put_nowait((pload_type, parsed))
            except:
                pass

        self.parsed_queue.cancel_join_thread()
        self.parsed_queue.close()


class DuplesUDPSender:
    DEF_RTAP = b'\x00\x00\x08\x00\x00\x00\x00\x00'
    def __init__(self, ip, port):
        self.dest_ip = ip
        self.dest_port = port
        self.send_socket = socket(AF_INET, SOCK_DGRAM)
        self.header = DuplesHeader()
    
    def send(self, data, addradiotap=False, ptype=defs.DUPLES_PAYLOAD_RTAP):
        assert type(ptype) is int, f"Invalid packet type ({ptype}).  Must be int type."
        if addradiotap:
            pload = self.DEF_RTAP + bytes(data)
        else:
            pload = bytes(data)
        self.header.pload_size = len(pload)
        self.header.pload_type = ptype
        packet = self.header.pack() + pload
        self.send_socket.sendto(packet, (self.dest_ip, self.dest_port))


if __name__ == "__main__":
    pass
