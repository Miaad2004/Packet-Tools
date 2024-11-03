import socket
import struct
import IP
import UDP
import random
import enum

class QueryType(enum.Enum):
    A = 1       # IPv4 address
    AAAA = 28   # IPv6 address
    MX = 15     # Mail exchange
    CNAME = 5   # Canonical name
    NS = 2      # Name server
    SOA = 6     # Start of authority
    PTR = 12    # Pointer record
    TXT = 16    # Text record
