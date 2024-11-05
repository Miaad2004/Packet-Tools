import socket
import struct
import random
from enum import Enum
from utils import Utils

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
    
    def build_header(self, payload_length_bytes: int) -> bytes:
        ihl_words = self.internet_header_length // 4 
        self.total_length = self.internet_header_length + payload_length_bytes
        source_ip = Utils.ip_to_bytes(self.source_ip)
        dest_ip = Utils.ip_to_bytes(self.destination_ip)
        
        flags = (self.flag_reserved << 2) + (self.flag_dont_fragment << 1) + self.flag_more_fragments    # 3 bits
        
        ip_header = struct.pack("!BBHHHBBH4s4s",
                                (self.version << 4) + ihl_words,
                                (self.DSCP << 2) + self.ECN,
                                self.total_length,
                                self.identification ,
                                (flags << 13) + self.fragment_offset,
                                self.ttl,
                                self.protocol,
                                self.header_checksum,
                                source_ip,
                                dest_ip,
                                )
        
        self.header_checksum = Utils.calculate_checksum(ip_header)
        ip_header = struct.pack("!BBHHHBBH4s4s",
                                (self.version << 4) + ihl_words,
                                (self.DSCP << 2) + self.ECN,
                                self.total_length,
                                self.identification ,
                                (flags << 13) + self.fragment_offset,
                                self.ttl,
                                self.protocol,
                                self.header_checksum,
                                source_ip,
                                dest_ip,
                                )
        
        return ip_header
    
    @staticmethod
    def from_bytes(ip_header_bytes: bytes):
        version_ihl, dscp_ecn, total_length, identification, flags_fragment_offset, ttl, protocol, header_checksum, source_ip, dest_ip = struct.unpack("!BBHHHBBH4s4s", ip_header_bytes)
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        dscp = dscp_ecn >> 2
        ecn = dscp_ecn & 0x03
        flags = flags_fragment_offset >> 13
        dont_fragment = (flags_fragment_offset >> 1) & 0x01
        more_fragments = flags_fragment_offset & 0x01
        fragment_offset = flags_fragment_offset & 0x1FFF
        source_ip = Utils.bytes_to_ip(source_ip)
        dest_ip = Utils.bytes_to_ip(dest_ip)
        
        ip_header = IPHeader(source_ip, dest_ip, IPProtocol(protocol))
        ip_header.version = version
        ip_header.internet_header_length = ihl
        ip_header.DSCP = dscp
        ip_header.ECN = ecn
        ip_header.total_length = total_length
        ip_header.identification = identification
        ip_header.flag_reserved = flags
        ip_header.flag_dont_fragment = dont_fragment
        ip_header.flag_more_fragments = more_fragments
        ip_header.fragment_offset = fragment_offset
        ip_header.ttl = ttl
        ip_header.protocol = protocol
        ip_header.header_checksum = header_checksum
        return ip_header

class IPPacket:
    def __init__(self, header: IPHeader, payload: bytes):
        self.header = header
        self.payload = payload

    def build_packet(self) -> bytes:
        ip_header = self.header.build_header(len(self.payload))
        return ip_header + self.payload
