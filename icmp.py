import socket
import os
import struct
import time
from enum import Enum
import subprocess
import platform
import atexit
import IP

class ICMPType(Enum):
    ECHO_REPLY = 0  # Echo reply (used to ping)
    DEST_UNREACHABLE = 3  # Destination Unreachable
    SOURCE_QUENCH = 4  # Source Quench (deprecated)
    REDIRECT_MESSAGE = 5  # Redirect Message
    ECHO_REQUEST = 8  # Echo request (used to ping)
    ROUTER_ADVERTISEMENT = 9  # Router Advertisement
    ROUTER_SOLICITATION = 10  # Router Solicitation
    TIME_EXCEEDED = 11  # Time to live (TTL) expired in transit
    PARAMETER_PROBLEM = 12  # Parameter Problem: Bad IP header
    TIMESTAMP = 13  # Timestamp

class ICMP:
    incoming_buffer_size = 1024
    
    def __init__(self):
        pass
    
    @staticmethod
    def _create_socket(custom_IP_header=True):
         my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
         if custom_IP_header:
             my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
         
         return my_socket
         

    @staticmethod
    def _calculate_checksum(packet):
        # add padding for odd length
        if len(packet) % 2 == 1:
            packet += b'\x00'   # add a zero byte
        
        checksum = 0
        
        for i in range(0, len(packet), 2):
            # add up 2 bytes by 2 bytes
            checksum += (packet[i] << 8) + packet[i + 1]
            carry = checksum >> 16
            
            # mask with 0xFFFF to limit sum to 16 bits
            check_sum_16_bit = checksum & 0xFFFF   
            
            # Wrap around carry 
            checksum = check_sum_16_bit + carry
        
        # ones complement & and mask it to 16 bits
        checksum = ~checksum & 0xFFFF
        return checksum
