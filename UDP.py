import struct
from IP import IPProtocol

# Based on https://en.wikipedia.org/wiki/User_Datagram_Protocol
class UDPPacket:
    def __init__(self, source_ip: str, dest_ip: str, source_port: int, dest_port: int):
        assert source_port >= 0 and source_port <= 2**16 - 1
        assert dest_port >= 0 and dest_port <= 2**16 - 1
        
        self.source_port = source_port   # 2 bytes
        self.dest_port = dest_port       # 2 bytes
        self.total_length = 0            # 2 bytes (header + data)
        self.checksum = 0                # 2 bytes
        
        # for checksum
        self.source_ip = source_ip
        self.dest_ip = dest_ip
    
    @staticmethod
    def ip_to_bytes(ipv4: str):
        parts = map(int, ipv4.split("."))
        return bytes(parts)
    
    def get_pseudo_header(self, udp_length):
        source_ip = self.ip_to_bytes(self.source_ip)
        dest_ip = self.ip_to_bytes(self.dest_ip)
        
        pseudo_header = struct.pack("!4s4sHH",
                                    source_ip, dest_ip, udp_length,
                                    (0 << 8)+ IPProtocol.UDP.value)
        
        return pseudo_header
        
    def calculate_checksum(self, packet_header):
        # pad even packets
        if len(packet_header) % 2 == 1:
            packet_header += b'\x00'     # add a zero byte
        
        checksum = 0
        for i in range(0, len(packet_header), 2):
            # add 2 bytes by 2 bytes
            checksum += (packet_header[i] << 8) + packet_header[i + 1]
            carry = checksum >> 16
            
            # mask to 16 bits and wrap around carry
            checksum = (checksum & 0xFFFF) + carry

        # one's complement and mask to 16 bits
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def build_packet(self, payload: bytes):
        assert len(payload) <= 2**16 - 1 - 8 - 20  # 8 byte UDP header and 20 bytes ip header
        
        self.total_length = 8 + len(payload)
        
        packet = struct.pack("!HHHH",
                             self.source_port, self.dest_port,
                             self.total_length, self.checksum)
        packet += payload
        
        self.checksum = self.calculate_checksum(self.get_pseudo_header(udp_length=len(packet)) + packet)
        packet = struct.pack("!HHHH",
                            self.source_port, self.dest_port,
                            self.total_length, self.checksum)
        packet += payload
        
        return packet
    
    @staticmethod
    def from_bytes(udp_packet_bytes: bytes):
        source_port, dest_port, total_length, checksum = struct.unpack("!HHHH", udp_packet_bytes[:8])
        payload = udp_packet_bytes[8:]
        
        udp_packet = UDPPacket(source_port=source_port, dest_port=dest_port)
        udp_packet.total_length = total_length
        udp_packet.checksum = checksum
        
        return udp_packet, payload

