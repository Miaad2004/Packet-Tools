import struct
from enum import Enum
from utils import Utils

class EthernetType(Enum):
    IPv4 = 0x0800
    ARP = 0x0806
    IPv6 = 0x86DD


class EthernetFrame:
    def __init__(self, source_mac, dest_mac, payload: bytes, ethertype: EthernetType, use_software_crc: bool = True):
        self.source_mac = source_mac
        self.dest_mac = dest_mac
        self.ethertype = ethertype
        self.payload = payload
        self.use_software_crc = use_software_crc
    
    @staticmethod
    def _calculate_CRC(frame: bytes):
        pass
    
    def build_frame(self):
        header = struct.pack('!6s6sH', 
                             Utils.mac_to_bytes(self.dest_mac), 
                             Utils.mac_to_bytes(self.source_mac), 
                             self.ethertype.value)
        
        frame = header + self.payload
        if self.use_software_crc:
            crc = self._calculate_CRC(frame)
            frame += crc
            
        return frame
        
    
        