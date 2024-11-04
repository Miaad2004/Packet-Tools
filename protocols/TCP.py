import protocols.IP as IP
import struct
import socket
from utils.utils import utils
import random
from utils.utils import Utils

class TCPHeader:
    def __init__(self, source_ip: str, dest_ip: str, source_port: int, dest_port: int):
        self.source_ip = source_ip       # 32 bits 
        self.dest_ip = dest_ip           # 32 bits 
        self.source_port = source_port   # 16 bits
        self.dest_port = dest_port       # 16 bits

        self.sequence_number = 0         # 32 bits
        self.ack_number = 0              # 32 bits
        self.data_offset = 5             # 4 bits (default TCP header size without options)
        self.reserved = 0                # 4 bits
        self.CWR = 0   # 1 bit    
        self.ECE = 0   # 1 bit
        self.URG = 0   # 1 bit
        self.ACK = 0   # 1 bit
        self.PSH = 0   # 1 bit
        self.RST = 0   # 1 bit
        self.SYN = 0   # 1 bit
        self.FIN = 0   # 1 bit
        self.window = 8192         # 16 bits (default value)
        self.checksum = 0          # 16 bits
        self.urgent_pointer = 0    # 16 bits
        #self.options = 0           # 32 bits
    
    def _get_pseudo_header(self, tcp_packet_length):
        pseudo_header = struct.pack("!4s4sBBH",
                                    utils.ip_to_bytes(self.source_ip), utils.ip_to_bytes(self.dest_ip),
                                    0, IP.IPProtocol.TCP.value, tcp_packet_length)
        return pseudo_header
    
    def build_header(self):
        flags = (self.data_offset << 12) + (self.reserved << 8) + (self.CWR << 7) + \
                (self.ECE << 6) + (self.URG << 5) + (self.ACK << 4) + (self.PSH << 3) + \
                (self.RST << 2) + (self.SYN << 1) + self.FIN
                
        # Pack header with a placeholder checksum
        header = struct.pack("!HHIIHHHH",
                             self.source_port, self.dest_port, 
                             self.sequence_number, self.ack_number,
                             flags, self.window, 
                             self.checksum, self.urgent_pointer, 
        )#self.options)
        print(len(header))
        
        pseudo_header = self._get_pseudo_header(len(header + self.payload))
        self.checksum = Utils.calculate_checksum(pseudo_header + header + self.payload)

        header = struct.pack("!HHIIHHHH",
                             self.source_port, self.dest_port, 
                             self.sequence_number, self.ack_number,
                             flags, self.window, 
                             self.checksum,
                             self.urgent_pointer, )
                             #self.options)
        
        return header

class TCPPacket:
    def __init__(self, header: TCPHeader, payload: bytes):
        self.header = header
        self.payload = payload

    def build_packet(self):
        tcp_header = self.header.build_header()
        return tcp_header + self.payload

        
class TCP:
    def __init__(self):
        pass
    
    def handshake(self):
        pass
    

def test():
    source_ip = "192.168.1.6"
    dest_ip = "192.168.1.1"
    tcp_header = TCPHeader(source_ip, dest_ip, 5462, 80)
    
    # SYN packet settings
    tcp_header.SYN = 1
    tcp_header.sequence_number = random.randint(1, 50)
    tcp_packet = TCPPacket(tcp_header, b"")
    packet = tcp_packet.build_packet()
    
    # Build IP packet
    ip_packet = IP.IPHeader(source_ip, dest_ip, IP.IPProtocol.TCP).build_packet(len(packet))
    final_packet = ip_packet + packet
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(final_packet, (dest_ip, 80))
    

    
    
    
test()