from IP import IPHeader, IPProtocol, IPPacket
import Ethernet
import struct
import socket
import random
from utils import Utils
import collections
from enum import Enum
import time
import threading

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
    SYN_SENT = 2
    ESTABLISHED = 4
    CLOSING = 8
    LAST_ACK = 9
    WAITING_GOR_FINAL_ACK = 10
    NOT_INITIALIZED = 11
        


class TCPPacket:
    def __init__(self, header: TCPHeader, payload: bytes = b""):
        self.header = header
        self.payload = payload
        self.header.payload = payload  
        self.send_or_recv_time = None
        

    def build_packet(self):
        tcp_header = self.header.build_header()
        return tcp_header + self.payload


class TCPConnection:
    """
    simple tcp implementation using raw sockets
    
    * Doesn't support packet fragmentation
    * Doesn't support flow control
    * Doesn't support congestion control
    * Doesn't support options in TCP header
    * Supports handshaking, simple data transfer, graceful close, retransmission, and abort
    
    """
    def __init__(self, source_MAC: str, dest_MAC: str, source_ip: str, dest_ip: str, source_port: int, dest_port: int, interface: str):
        self.source_MAC = source_MAC
        self.dest_MAC = dest_MAC
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.interface = interface
        
        self.verbose = 1
        
        # TCB (Transmission Control Block)
        self.retransmission_queue = collections.deque()
        self.send_buffer = []
        self.receive_buffer = []
        self.current_segment = None
        self.connection_state = ConnectionState.NOT_INITIALIZED
        
        self.our_seq_number = random.randint(0, 2**32 - 1)
        self.server_seq_number = None
        
        
        self.retransmission_timeout = 5
        self.keep_alive_timeout = 20
        self.last_activity_time = None
        
        # Threads
        self.listener_thread = threading.Thread(target=self._listen)
        self.timer_thread = threading.Thread(target=self._timer)    # for retransmission, keep alive etc.
        
        
        # In Linux "Receiving of all IP protocols via IPPROTO_RAW is not possible using raw sockets."
        # source: https://stackoverflow.com/questions/40795772/cant-receive-packets-to-raw-socket
        # So I used one raw socket (IPPROTO_RAW) for sending (with custom IP header)
        # and another raw socket (IPPROTO_TCP) for receiving TCP packets
        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    def create_packet(self, SYN: bool, ACK: bool, FIN: bool, RST: bool, payload: bytes = b""):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.SYN = SYN
        tcp_header.ACK = ACK
        tcp_header.FIN = FIN
        tcp_header.RST = RST
        tcp_header.sequence_number = self.our_seq_number
        if ACK:
            tcp_header.ack_number = self.server_seq_number
        tcp_packet = TCPPacket(tcp_header, payload)
        return tcp_packet
    
    # **** Main Thread methods ****
    def send_packet(self, tcp_packet: TCPPacket): 
        tcp_packet.send_or_recv_time = Utils.get_current_time()
        tcp_packet_built = tcp_packet.build_packet()
        
        # Create IP header
        ip_header = IPHeader(self.source_ip, self.dest_ip, IPProtocol.TCP)
        ip_packet = IPPacket(ip_header, tcp_packet_built).build_packet()
        
         
        # create Ethernet header
        frame = Ethernet.EthernetFrame(self.source_MAC, self.dest_MAC, ip_packet, Ethernet.EthernetType.IPv4, use_software_crc=False).build_frame()
        
        # port is set to 0 because we are sending raw IP packets
        self.send_sock.sendto(frame, (self.interface, 0))
        self.retransmission_queue.append(tcp_packet)
        
        if tcp_packet.header.SYN or tcp_packet.header.FIN:
            self.our_seq_number += 1
        # if not tcp_packet.header.ACK and len(tcp_packet.payload) == 0:
        #     self.our_seq_number += 1
        
        if len(tcp_packet.payload) > 0:
            self.our_seq_number += len(tcp_packet.payload) 
    
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
    
    def _listen_for_handshake(self, timeout: int = 1):
        ip_header, tcp_header, _ = self._listen(timeout)
        
        # check ack numbers
        if tcp_header.ack_number != self.our_seq_number:
            if self.verbose:
                print(f"Invalid ack number. expected {self.our_seq_number}, got {tcp_header.ack_number}")
            return False
        
        # check for reset
        if tcp_header.RST:
            if self.verbose:
                print("Connection reset by peer")
            return False
        
        # check for SYN, ACK
        if not tcp_header.SYN or not tcp_header.ACK:
            if self.verbose:
                print("Not a SYN-ACK packet")
            return False
        
        # packet verified
        self.server_seq_number = tcp_header.sequence_number
        if self.verbose:
            print(f"SYN-ACK packet received. server seq number: {self.server_seq_number}")
        
        return True
    
    def _parse_packet(self, packet):
        if len(packet) < 40:
            raise ValueError("Packet is too small to be a TCP packet")
        
        ip_header = IPHeader.from_bytes(packet[:20])
        tcp_header = TCPHeader.from_bytes(packet[20:40])
        payload = packet[40:]
        
        return ip_header, tcp_header, payload
    
    def _send_reset(self):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.RST = 1
        tcp_header.sequence_number = self.our_seq_number
        
        tcp_packet = TCPPacket(tcp_header)
        self.send_packet(tcp_packet)
        if self.verbose:
            print(f"RST packet sent with seq number: {self.our_seq_number}")
    
    def _send_fin(self):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.FIN = 1
        tcp_header.sequence_number = self.our_seq_number
        tcp_packet = TCPPacket(tcp_header)
        self.send_packet(tcp_packet)
        self.our_seq_number += 1
        
        if self.verbose:
            print(f"FIN packet sent with seq number: {self.our_seq_number}")
    
    def perform_half_hadnshake(self, timeout: int = 1):
        self._send_syn()
        
        # Wait for SYN-ACK
        try:
            if not self._listen_for_handshake(timeout):
                return False
        
        except socket.timeout:
            print("Timeout waiting for SYN-ACK")
            raise
    
    def perform_handshake(self, timeout: int = 1):
        self._send_syn()
        self.connection_state = ConnectionState.SYN_SENT
        
        # Wait for SYN-ACK
        try:
            if not self._listen_for_handshake(timeout):
                return False
            self.connection_state = ConnectionState.SYN_RECEIVED
        
        except socket.timeout:
            if self.verbose:
                print("Timeout waiting for SYN-ACK")
            raise
        
        # send ACK
        self._send_ack()
        self.connection_state = ConnectionState.ESTABLISHED
        
        if self.verbose:
            print("Handshake complete")
    
    def _listen_for_finack(self, timeout: int = 1):
        self.recv_socket.settimeout(timeout)
        
        while True:
            packet = self.recv_socket.recv(4096)
            ip_header, tcp_header, payload = self._parse_packet(packet)
            
            # check ports
            if tcp_header.source_port != self.dest_port and tcp_header.dest_port != self.source_port:
                continue
            
            # check ack numbers
            if tcp_header.ack_number != self.our_seq_number:
                if self.verbose:
                    print(f"Invalid ack number. expected {self.our_seq_number}, got {tcp_header.ack_number}")
                continue
            
            # check for reset
            if tcp_header.RST:
                if self.verbose:
                    print("Connection reset by peer")
                continue
            
            # check for FIN, ACK
            if not tcp_header.FIN or not tcp_header.ACK:
                if self.verbose:
                    print("Not a FIN-ACK packet")
                continue
            
            self.server_seq_number = tcp_header.sequence_number
            
            if self.verbose:
                print(f"FIN-ACK packet received. seq number: {tcp_header.sequence_number}")
            
            return True
        
    
    def open():
        pass
    
    def close(self):
        assert self.connection_state == ConnectionState.ESTABLISHED, "Connection is not established"
        
        if self.connection_state == ConnectionState.ESTABLISHED:
            self.connection_state = ConnectionState.FIN_WAIT_1
        
        self._send_fin()
        
        # Wait for FIN-ACK
        try:
            if not self._listen_for_finack():
                return False
        
        except socket.timeout:
            self.abort()
            if self.verbose:
                print("Timeout waiting for FIN-ACK")
            raise
        
        time.sleep(0.5)
        # send final ACK
        self._send_ack()
        
        
    
    def send():
        pass
    
    def receive():
        pass
    
    def abort(self):
        self._send_reset()
        self.connection_state = ConnectionState.CLOSED
        if self.verbose:
            print("Connection aborted")
            
    
    def status(self):
        return self.connection_state
    
    
    

def test():
    interface = 'eth0'
    source_MAC = "00:15:5d:69:b4:e5"
    dest_MAC = "00:15:5d:ac:5f:57"
    source_ip = "172.18.121.202"
    dest_ip = "192.168.1.1"
    source_port = random.randint(1024, 65535)
    dest_port = 80
    
    tcp_connection = TCPConnection(source_MAC, dest_MAC, source_ip, dest_ip, source_port, dest_port, interface)
    tcp_connection.perform_handshake()
    time.sleep(2)
    tcp_connection.close()
    time.sleep(2)
    #tcp_connection.abort()

test()
    