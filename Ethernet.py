import struct
from enum import Enum
from utils import Utils

class EthernetType(Enum):
    IPv4 = 0x0800
    ARP = 0x0806
    IPv6 = 0x86DD

