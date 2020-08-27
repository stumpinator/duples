import sys
from duples import *

rs_receiver = DuplesUDPReceiver()

def filterpkt(pkt):
    if pkt.TYPE_ENUM() == UwifiPacket.WLAN_FRAME_TYPES["MGMT"]:
        return True
    return False

def signal_handler(signal, frame):
    rs_receiver.active.clear()

if __name__ == "__main__":
    if (len(sys.argv) != 3):
        print("Expected 2 arguments.")
        print(f"Usage: {sys.argv[0]} <ip> <port>")
        sys.exit()

    ip = sys.argv[1]
    port = int(sys.argv[2])

    rs_receiver.initialize(ip, port, parsers=4, pktfilter=filterpkt)
    
    #trap SIGINT (e.g. CTRL+C)
    #should probably grab SIGHUP here as well
    signal.signal(signal.SIGINT, signal_handler)
    
    rs_receiver.startprocessing()

    count = 0
    while rs_receiver.active.is_set():
        #grab items placed onto the queue by the parsing/filtering threads
        try:
            parsed = rs_receiver.log_queue.get(block=True,timeout=0.5)
        except:
            continue
        #count += 1
        #print(f"TYPE: {parsed.TYPE()} SUBTYPE: {parsed.SUBTYPE()} - QSIZE: {rs_receiver.log_queue.qsize()}")
        if type(parsed) == UwifiPacket:
            print(f"TA: {parsed.TA()} RA: {parsed.RA()} BSSID: {parsed.BSSID()} SIG: {parsed.phy_signal} FREQ: {parsed.phy_freq} SSID: {parsed.SSID()}")
        
    
    rs_receiver.stopprocessing()
