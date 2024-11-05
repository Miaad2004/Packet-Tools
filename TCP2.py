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
    @staticmethod
    def from_bytes(tcp_header_bytes: bytes):
        source_port, dest_port, sequence_number, ack_number, \
        flags, window, checksum, urgent_pointer = struct.unpack("!HHIIHHHH", tcp_header_bytes)
        
        tcp_header = TCPHeader("", "", source_port, dest_port)
        tcp_header.sequence_number = sequence_number
        tcp_header.ack_number = ack_number
        tcp_header.data_offset = flags >> 12
        tcp_header.reserved = (flags >> 8) & 0xF
        tcp_header.CWR = (flags >> 7) & 1
        tcp_header.ECE = (flags >> 6) & 1
        tcp_header.URG = (flags >> 5) & 1
        tcp_header.ACK = (flags >> 4) & 1
        tcp_header.PSH = (flags >> 3) & 1
        tcp_header.RST = (flags >> 2) & 1
        tcp_header.SYN = (flags >> 1) & 1
        tcp_header.FIN = flags & 1
        tcp_header.window = window
        tcp_header.checksum = checksum
        tcp_header.urgent_pointer = urgent_pointer
        
        return tcp_header

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
    def __init__(self, source_MAC: str, dest_MAC: str, source_ip: str, dest_ip: str, source_port: int, dest_port: int, interface: str):
        self.source_MAC = source_MAC
        self.dest_MAC = dest_MAC
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.interface = interface
        
        self.retransmission_queue = collections.deque()
        self.send_buffer = []
        self.receive_buffer = []
        self.current_segment = None
        self.connection_state = ConnectionState.CLOSED
        
        self.our_seq_number = random.randint(0, 2**32 - 1)
        self.server_seq_number = None
        self.verbose = 1
        
        # In Linux "Receiving of all IP protocols via IPPROTO_RAW is not possible using raw sockets."
        # source: https://stackoverflow.com/questions/40795772/cant-receive-packets-to-raw-socket
        # So I used one raw socket (IPPROTO_RAW) for sending (with custom IP header)
        # and another raw socket (IPPROTO_TCP) for receiving TCP packets
        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    def send_packet(self, tcp_packet: TCPPacket): 
        tcp_packet.send_or_recv_time = Utils.get_current_time()
        tcp_packet = tcp_packet.build_packet()
        
        # Create IP header
        ip_header = IPHeader(self.source_ip, self.dest_ip, IPProtocol.TCP)
        ip_packet = IPPacket(ip_header, tcp_packet).build_packet()
        
         
        # create Ethernet header
        frame = Ethernet.EthernetFrame(self.source_MAC, self.dest_MAC, ip_packet, Ethernet.EthernetType.IPv4, use_software_crc=False).build_frame()
        
        # port is set to 0 because we are sending raw IP packets
        self.send_sock.sendto(frame, (self.interface, 0))
        self.retransmission_queue.append(tcp_packet)
    
    def _send_syn(self):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.SYN = 1
        tcp_header.sequence_number = self.our_seq_number
        tcp_packet = TCPPacket(tcp_header)
        self.send_packet(tcp_packet)
        self.our_seq_number += 1
        
        if self.verbose:
            print("SYN packet sent")
    
    def _send_ack(self):
        self.server_seq_number += 1
        
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.ACK = 1
        
        tcp_header.sequence_number = self.our_seq_number
        tcp_header.ack_number = self.server_seq_number 
        tcp_packet = TCPPacket(tcp_header)

        self.send_packet(tcp_packet)
        
        if self.verbose:
            print(f"ACK packet sent with seq number: {self.our_seq_number}, ack number: {self.server_seq_number + 1}")
    
    def _listen(self, timeout: int = 1):
        self.recv_socket.settimeout(timeout)
        
        while True:
            packet = self.recv_socket.recv(4096)
            ip_header, tcp_header, payload = self._parse_packet(packet)
            
            # check ports
            if tcp_header.source_port != self.dest_port and tcp_header.dest_port != self.source_port:
                continue
            
            # packet verified
            if self.verbose:
                print(f"Packet received. seq number: {tcp_header.sequence_number}")
            
            break
        
        return ip_header, tcp_header, payload
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
    
    
    
    