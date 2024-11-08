import socket
import struct
import IPv4
import UDP
import random
import enum
from Ethernet import EthernetFrame, EthernetType

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
    
    @staticmethod
    def parse_packet(packet: bytes):
        header = struct.unpack("!HHHHHH", packet[:12])
        transaction_id, flags, n_queries, n_answers, ns_count, na_count = header
        
        # Debug logging
        print(f"Parsing DNS packet of length: {len(packet)}")
        print(f"Transaction ID: {transaction_id}")
        print(f"Flags: {bin(flags)}") 
        print(f"Answers: {n_answers}")
        
        offset = 12
        
        # Skip question section using compression pointer awareness
        for _ in range(n_queries):
            while offset < len(packet):
                length = packet[offset]
                if length & 0xC0:  # Check for compression pointer
                    offset += 2    # Skip compression pointer
                    break
                elif length == 0:  # End of name
                    offset += 1
                    break
                offset += length + 1
            offset += 4  # Skip QTYPE and QCLASS
        
        # Parse answer section with compression pointer handling
        for _ in range(n_answers):
            if offset >= len(packet):
                return None
                
            # Handle name compression in answer
            if packet[offset] & 0xC0:  # Compression pointer
                offset += 2
            else:
                while packet[offset] != 0:
                    offset += packet[offset] + 1
                offset += 1
            
            type_, class_, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset+10])
            offset += 10
            
            if type_ == QueryType.A.value:
                try:
                    ipv4 = struct.unpack("!BBBB", packet[offset:offset+4])
                    return ".".join(map(str, ipv4))
                except struct.error:
                    print(f"Error unpacking IPv4 at offset {offset}")
                    return None
            
            offset += rdlength
        return None
    
    @staticmethod
    def domain_to_ipv4(domain: str, source_ip: str, source_mac: str, dest_mac: str, dns_server: str = "8.8.8.8", source_port: int = 12345, dest_port: int = 53):
        dns_client = DNS()
        dns_query = dns_client.build_packet(domain, QueryType.A)
    
        dest_ip = dns_server
    
        udp_packet = UDP.UDPPacket(source_ip, dest_ip, source_port, dest_port)
        udp_packet = udp_packet.build_packet(dns_query)
    
        ip_header = IPv4.IPHeader(source_ip, dest_ip, IPv4.IPProtocol.UDP)
        ip_packet = IPv4.IPPacket(ip_header, udp_packet).build_packet()
    
        ip_payload = ip_packet
    
        ethernet_frame = EthernetFrame(source_mac, dest_mac, ip_payload, EthernetType.IPv4, use_software_crc=False)
        ethernet_packet = ethernet_frame.build_frame()
    
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
            s.bind(("eth0", 0))
            s.send(ethernet_packet)
    
            try:
                response = s.recv(65535)
                print("Received response from DNS server.")
                print("Raw DNS Response:", response[42:].hex())
                dns_response = response[42:]
                ipv4_address = DNS.parse_packet(dns_response)
                return ipv4_address
    
            except socket.timeout:
                print("Request timed out.")
                return None

if __name__ == "__main__":
    interface = 'eth0'
    source_MAC = "00:15:5d:69:b4:e5"
    dest_MAC = "00:15:5d:ac:5f:57"
    source_ip = "172.18.121.202"
    print(DNS.domain_to_ipv4("google.com", source_ip, source_MAC, dest_MAC))