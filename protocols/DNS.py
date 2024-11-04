import socket
import struct
import protocols.IP as IP
import protocols.UDP as UDP
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
        
    
    def build_packet(self, query: str , query_type: QueryType = QueryType.A.value, query_class: int = 1):
            flags = (self.QR << 15) + (self.opcode << 11) + (self.AA << 10) + \
                    (self.TC << 9) + (self.RD << 8) + (self.RA << 7) + (self.Z << 4) + self.RCODE
            header = struct.pack("!HHHHHH", self.transaction_id, flags, self.n_queries,
                                 self.n_answers, self.ns_count, self.na_count)
            
            q = self._build_query(query, query_type, query_class)
            
            return header + q
        
        
        

    
def test(query, source_ip, dest_ip, source_port=12345, dest_port=53, query_type=QueryType.A):
    dns_client = DNS()
    dns_query = dns_client.build_packet(query, query_type)
    
    udp_packet = UDP.UDPPacket(source_ip, dest_ip, source_port, dest_port)
    udp_payload = dns_query
    udp_header = udp_packet.build_packet(udp_payload)
    
    ip_packet = IP.IPHeader(source_ip, dest_ip, IP.IPProtocol.UDP)
    ip_header = ip_packet.build_packet(payload_length_bytes=len(udp_header))
    
    packet = ip_header + udp_header
    
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(packet, (dest_ip, 0))
    
        print(f"Sent DNS query for {query} ({query_type.name}) to {dest_ip}")

        # Step 5: Receive the response
        try:
            response = s.recv(65535)  # Large buffer size to capture full response
            print("Received response from DNS server.")
            print("Response (hex):", response.hex())  # Print raw response in hex
        except socket.timeout:
            print("Request timed out.")



# Test for an IPv6 address record (AAAA)
test("google.com", "192.168.1.3", "8.8.8.8", query_type=QueryType.AAAA)

# Test for a Mail Exchange (MX) record
test("google.com", "192.168.1.3", "8.8.8.8", query_type=QueryType.MX)

# Test for a Canonical Name (CNAME) record
test("google.com", "192.168.1.3", "8.8.8.8", query_type=QueryType.CNAME)