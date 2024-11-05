from IP import IPHeader, IPProtocol, IPPacket
import struct
import socket
import random
from utils import Utils

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

class TCPPacket:
    def __init__(self, header: TCPHeader, payload: bytes):
        self.header = header
        self.payload = payload
        self.header.payload = payload  

    def build_packet(self):
        tcp_header = self.header.build_header()
        return tcp_header + self.payload



# Assuming TCPHeader and TCPPacket are defined elsewhere as well
class TCPConnection:
    def __init__(self, source_ip, dest_ip, source_port, dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.sequence_number = random.randint(0, 4294967295)
        self.ack_number = 0
        
        # Socket for sending with custom IP header
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
        # Socket for receiving TCP packets
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.recv_sock.bind((source_ip, 0))
        self.recv_sock.settimeout(10.0)

    def send_packet(self, tcp_packet):
        # Create IP header
        ip_header = IPHeader(self.source_ip, self.dest_ip, IPProtocol.TCP)
        ip_packet = IPPacket(ip_header, tcp_packet)
        
        # Send packet using send socket
        self.send_sock.sendto(ip_packet.build_packet(), (self.dest_ip, 0))

    def send_syn(self):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.sequence_number = self.sequence_number
        tcp_header.SYN = 1
        tcp_packet = TCPPacket(tcp_header, b"").build_packet()

        self.send_packet(tcp_packet)
        print("SYN packet sent")

    def receive_syn_ack(self):
        while True:
            try:
                raw_data, addr = self.recv_sock.recvfrom(65535)
                
                # Skip IP header
                tcp_header = raw_data[20:40]
                
                # Parse TCP header
                tcp_fields = struct.unpack('!HHIIBBHHH', tcp_header[:20])
                src_port = tcp_fields[0]
                dst_port = tcp_fields[1]
                seq_num = tcp_fields[2]
                ack_num = tcp_fields[3]
                flags = tcp_fields[5]
                
                # Extract SYN and ACK flags
                syn = (flags & 0x02) >> 1
                ack = (flags & 0x10) >> 4
                
                # Verify this is the SYN-ACK we're waiting for
                if (src_port == self.dest_port and 
                    dst_port == self.source_port and 
                    syn == 1 and ack == 1):
                    print("SYN-ACK received")
                    self.ack_number = seq_num + 1
                    self.sequence_number += 1
                    break
                    
            except socket.timeout:
                print("Timeout waiting for SYN-ACK")
                raise

    def send_ack(self):
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.sequence_number = self.sequence_number
        tcp_header.ack_number = self.ack_number
        tcp_header.ACK = 1
        tcp_packet = TCPPacket(tcp_header, b"").build_packet()

        self.send_packet(tcp_packet)
        print("ACK sent. Handshake complete")

    def perform_handshake(self):
        self.send_syn()
        self.receive_syn_ack()
        self.send_ack()

    def close_connection(self):
        # Send FIN
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.sequence_number = self.sequence_number
        tcp_header.ack_number = self.ack_number
        tcp_header.FIN = 1
        tcp_packet = TCPPacket(tcp_header, b"").build_packet()
        
        self.send_packet(tcp_packet)
        print("FIN sent")

        # Wait for FIN-ACK
        while True:
            try:
                raw_data, addr = self.recv_sock.recvfrom(65535)
                tcp_header = raw_data[20:40]
                flags = struct.unpack('!B', tcp_header[13:14])[0]
                
                fin = flags & 0x01
                ack = (flags & 0x10) >> 4
                
                if fin == 1 and ack == 1:
                    print("FIN-ACK received")
                    break
            except socket.timeout:
                print("Timeout waiting for FIN-ACK")
                break

        # Send final ACK
        tcp_header = TCPHeader(self.source_ip, self.dest_ip, self.source_port, self.dest_port)
        tcp_header.sequence_number = self.sequence_number + 1
        tcp_header.ack_number = self.ack_number + 1
        tcp_header.ACK = 1
        tcp_packet = TCPPacket(tcp_header, b"").build_packet()
        
        self.send_packet(tcp_packet)
        print("Final ACK sent")

        # Cleanup
        self.send_sock.close()
        self.recv_sock.close()




a = TCPConnection("172.18.121.202", "192.168.1.1", 1235, 80)
a.perform_handshake()
a.close_connection()