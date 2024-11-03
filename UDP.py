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
