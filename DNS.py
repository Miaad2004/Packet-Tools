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

# Based on https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
class DNS:
    """
    DNS packet structure:
    ----------------------
    |       Header       |      
    ----------------------
    |      Question      |
    ----------------------
    |       Answer       |
    ----------------------
    |      Authority     |
    ----------------------
    |      Additional    |
    ----------------------
    """
    def __init__(self):
        self.transaction_id = random.randint(0, 2**15 - 1) # 16 bits
        self.QR = 0     # Query or Response | 1 bit
        self.opcode = 0 # Query Type | 4 bits 
        self.AA = 0     # Authoritative Answe | 1 bit
        self.TC = 0     # 1 bit
        self.RD = 1     # Recursion Desired | 1 bit
        self.RA = 0     # Recursion Available | 1 bit
        self.Z = 0      # For future use | 1 bit
        self.RCODE = 0  # Response Code | 1 bit
        self.n_queries = 1 # 16 bits
        self.n_answers = 0 # 16 bits
        self.ns_count = 0  # Number of name servers in Authority Section  | 16 bits
        self.na_count = 0  # Number of additional records (usually A record of name servers) | 16 bits
    
    @staticmethod
    def domain_to_label(domain: str) -> bytes:
        domain = domain.strip()
        parts = domain.split(".")
        parts = [struct.pack("!B", len(part)) + bytes(part, encoding='utf-8') for part in parts]
        return b"".join(parts) + b'\x00'
    
    def _build_query(self, query: str , query_type: QueryType = QueryType.A.value, query_class: int = 1):
        """ 
        DNS Query structure
        -------------------
        |       QNAME     |
        -------------------
        |       QTYPE     |
        -------------------
        |       QCLASS    |
        -------------------
        """
        if isinstance(query_type, QueryType):
            query_type = query_type.value
            
        query_name = self.domain_to_label(query)
        query = query_name +  struct.pack("!HH", query_type, query_class)
        
        return query
