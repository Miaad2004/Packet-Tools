import socket
import struct
import random
from enum import Enum

class IPProtocol(Enum):
    # Based on https://en.wikipedia.org/wiki/IPv4#DSCP
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
    ENCAP = 41
    OSPF = 89
    SCTP = 132
    

# Based on https://en.wikipedia.org/wiki/IPv4#DSCP
class IPHeader:
    def __init__(self, source_ip: str, dest_ip: str, protocol: IPProtocol, ttl=128):
        self.version = 4   # 4 bits
        self.internet_header_length = 20   # 4 bits, min is 20(no options)
        self.DSCP = 0   # 6 bits
        self.ECN = 0    # 2 bits
        self.total_length = 0   # 16 bits
        
        self.identification  = random.randint(0, 2**14)   # 16 bits
        self.flag_reserved = 0   # 1 bit
        self.flag_dont_fragment = 0   # 1 bit
        self.flag_more_fragments = 0   # 1 bit
        self.fragment_offset = 0    # 13 bits
        
        self.ttl = ttl      # 8 bits
        self.protocol = protocol.value    # 8 bits
        self.header_checksum = 0 # 16 bits
        
        self.source_ip = source_ip   # 32 bits
        self.destination_ip = dest_ip   # 32 bits
    
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
