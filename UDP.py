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
