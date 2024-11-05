from IP import IPHeader, IPProtocol, IPPacket
import struct
import socket
import random
from utils import Utils
import collections
from enum import Enum

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
        self.payload = b""         # Initialize payload as empty bytes
        #self.options = 0           # 32 bits
    
    def _get_pseudo_header(self, tcp_packet_length):
        pseudo_header = struct.pack("!4s4sBBH",
                                    Utils.ip_to_bytes(self.source_ip), Utils.ip_to_bytes(self.dest_ip),
                                    0, IPProtocol.TCP.value, tcp_packet_length)
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
                             self.checksum, self.urgent_pointer,)

        pseudo_header = self._get_pseudo_header(len(header) + len(self.payload))
        self.checksum = Utils.calculate_checksum(pseudo_header + header + self.payload)

        header = struct.pack("!HHIIHHHH",
                             self.source_port, self.dest_port, 
                             self.sequence_number, self.ack_number,
                             flags, self.window, 
                             self.checksum, self.urgent_pointer,)
        
        return header

class ConnectionState(Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10

class TCPPacket:
    def __init__(self, header: TCPHeader, payload: bytes):
        self.header = header
        self.payload = payload
        self.header.payload = payload  
        
        self.retransmission_queue = collections.deque()
        self.send_buffer = []
        self.receive_buffer = []
        current_segment = None
        

    def build_packet(self):
        tcp_header = self.header.build_header()
        return tcp_header + self.payload

class TCPConnection:
    def __init__(self):
        pass
    
    def perform_handshake(self):
        pass
    
    def open():
        pass
    
    def close():
        pass
    
    def send():
        pass
    
    def receive():
        pass
    
    def abort():
        pass
    
    def status():
        pass
    
    
    
    