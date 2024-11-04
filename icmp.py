import socket
import os
import struct
import time
from enum import Enum
import subprocess
import platform
import atexit
import protocols.IP as IP
from protocols.utils import Utils

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
    def send_packet(source_ipv4, destination_ipv4, icmp_type, sequence_num=1, ttl=64, 
                    icmp_code=0, process_id=os.getpid(),
                    my_socket=None, payload="", send_time=False):
        socket_created = False
        if my_socket is None:
            my_socket = ICMP._create_socket()
            socket_created = True

        if type(payload) != bytes:
            payload = bytes(payload, encoding='utf-8')
            
        if send_time:
            payload = struct.pack("d", time.perf_counter()) + payload
            
        try:
            # set ttl
            my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            
            checksum_val = 0
            process_id = process_id & 0xFFFF  # Limit process id to 16 bits
            
            # dummy header for calculating checksum
            icmp_header = struct.pack("!bbHHh", icmp_type.value, icmp_code, checksum_val, process_id, sequence_num)        
            icmp_packet = icmp_header + payload

            # add checksum
            checksum_val = Utils.calculate_checksum(icmp_packet)            
            icmp_header = struct.pack("!bbHHh", icmp_type.value, icmp_code, checksum_val, process_id, sequence_num) 
            icmp_packet = icmp_header + payload  
            
            # Create IP header
            ip_header = IP.IPHeader(source_ipv4, destination_ipv4, protocol=IP.IPProtocol.ICMP, ttl=ttl)
            ip_header = ip_header.build_packet(payload_length_bytes=len(icmp_packet))  
            packet = ip_header + icmp_packet
            
            my_socket.sendto(packet, (destination_ipv4, 1254))
        
        finally:
            if socket_created:
                my_socket.close()
        
        return 0


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
    def ping(source_ipv4, destination_ipv4, count=10, timeout=1, delay=1, payload_size_bytes=32):
        print(f"Pinging {destination_ipv4} with {count} packets:")
        min_rtt = float('inf')
        max_rtt = 0
        total_rtt = 0
        packets_sent = 0
        packets_received = 0
        
        # offset size of time sent as payload
        real_payload_size = max(0, payload_size_bytes - struct.calcsize('d'))
        
        with ICMP._create_socket() as s:
            for i in range(1, count + 1):
                payload = os.urandom(real_payload_size)
                ICMP.send_packet(source_ipv4, destination_ipv4, ICMPType.ECHO_REQUEST, sequence_num=i, my_socket=s, send_time=True, payload=payload)
                packets_sent += 1
                reply = ICMP.listen_for_reply(my_socket=s, timeout=timeout, verbose=False)
                
                if reply and reply['icmp_type'] == ICMPType.ECHO_REPLY:
                    send_time = struct.unpack("d", reply["payload"][0: struct.calcsize('d')])[0]
                    rtt = (reply["recv_time"] - send_time) * 1000  # RTT in milliseconds
                    total_rtt += rtt
                    min_rtt = min(min_rtt, rtt)
                    max_rtt = max(max_rtt, rtt)
                    packets_received += 1
                    print(f"Reply from {reply['destination_ip']}: seq={reply['sequence']} bytes={payload_size_bytes} time={rtt:.2f} ms")
                    
                else:
                    print(f"Request timed out for seq={i} after {timeout} seconds")
            
                time.sleep(delay)
        
        if packets_sent > 0:
            packet_loss = (packets_sent - packets_received) / packets_sent * 100
            
        else:
            packet_loss = 100.0  # If no packets sent, loss is 100%

        print(f"\nPing statistics for {destination_ipv4}:")
        print(f"\tPackets: Sent = {packets_sent}, Received = {packets_received}, {packet_loss:.2f}% packet loss,")
        print(f"\tMinimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {total_rtt / packets_received:.2f}ms")  
    
    @staticmethod
    def traceroute(source_ipv4, destination_ipv4, max_hops=20, timeout=2):
        ICMP._allow_icmp_ttl_exceeded()
        print(f"Tracerouting {destination_ipv4} with a maximum of {max_hops} hops:")
        
        with ICMP._create_socket() as s:
            sequence_number = 1
            for ttl in range(1, max_hops + 1):
                delays = []
                for i in range(3):  # Send three packets per hop
                    ICMP.send_packet(source_ipv4, destination_ipv4, ICMPType.ECHO_REQUEST, my_socket=s, sequence_num=sequence_number, ttl=ttl, send_time=True)
                    sequence_number +=1
                    reply = ICMP.listen_for_reply(my_socket=s, timeout=timeout, verbose=False)
                    
                    if reply:
                        if reply["icmp_type"] == ICMPType.ECHO_REPLY:
                            send_time = struct.unpack('d', reply['payload'][0: struct.calcsize('d')])[0]
                            delays.append(f"{(reply['recv_time'] - send_time) * 1000:.2f} ms")
                            destination_reached = True
                            
                        elif reply["icmp_type"] == ICMPType.TIME_EXCEEDED:
                            send_time = struct.unpack('d', reply['payload'][0: struct.calcsize('d')])[0]
                            delays.append(f"{(reply['recv_time'] - send_time) * 1000:.2f} ms")
                            
                        else:
                            delays.append("*")
                    else:
                        delays.append("*")
                
                # Print delays for this hop
                print(f"{ttl}\t{reply['destination_ip'] if reply else '*'}\t" + "\t".join(delays))
                
                # Stop if the destination reached
                if reply and reply["icmp_type"] == ICMPType.ECHO_REPLY:
                    print("Reached destination")
                    break
    
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

ICMP.ping("192.168.1.6","8.8.8.8")