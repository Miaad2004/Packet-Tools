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
    @staticmethod
    def listen_for_reply(my_socket, timeout=1, verbose=True):
        my_socket.settimeout(timeout)
        try:
            while True:
                packet, addr = my_socket.recvfrom(ICMP.incoming_buffer_size)
                recv_time = time.perf_counter()

                # Extract IP header and ICMP header
                ip_header = packet[0:20]
                icmp_header = packet[20:28]

                # Unpack ICMP header
                icmp_type, code, checksum, packet_id, sequence = struct.unpack("!bbHHh", icmp_header)

                # Return the relevant details
                return {
                    "icmp_type": ICMPType(value=icmp_type),
                    "recv_time": recv_time,
                    "sequence": sequence,
                    "destination_ip": addr[0], 
                    "ip_header": ip_header,
                    "icmp_header": icmp_header,
                    "payload": packet[28:]  
                }

        except socket.timeout as e:
            if verbose:
                print(f"Request timed out after {timeout} seconds")
    @staticmethod
    def _allow_icmp_ttl_exceeded(RULE_NAME = "Allow ICMP Time-Exceeded"):
        if platform.system() == "Windows":
            print("Requesting firewall permission to allow ICMP Time-Exceeded packets.")
            try:
                # Add firewall rule to allow ICMP Time-Exceeded packets
                subprocess.run([
                    "powershell", 
                    "-Command", 
                    f"New-NetFirewallRule -DisplayName '{RULE_NAME}' -Direction Inbound -Protocol ICMPv4 -IcmpType 11 -Action Allow"
                ], check=True)
                print(f"Firewall rule '{RULE_NAME}' added successfully.")
                
                # Register the cleanup function to delete the rule at the end
                atexit.register(ICMP._delete_icmp_rule)

            except subprocess.CalledProcessError:
                print("Failed to add firewall rule. Please run this script as Administrator.")
        else:
            print("ICMP firewall rule is only applicable on Windows. No action needed for this platform.")

    @staticmethod
    def _delete_icmp_rule(RULE_NAME = "Allow ICMP Time-Exceeded"):
        if platform.system() == "Windows":
            print(f"Deleting firewall rule '{RULE_NAME}'.")
            try:
                subprocess.run([
                    "powershell",
                    "-Command",
                    f"Remove-NetFirewallRule -DisplayName '{RULE_NAME}'"
                ], check=True)
                print(f"Firewall rule '{RULE_NAME}' deleted successfully.")
                
            except subprocess.CalledProcessError:
                print(f"Failed to delete firewall rule '{RULE_NAME}'. You may need to remove it manually.")
