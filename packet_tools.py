import socket
import time
import argparse
import threading
import argparse
from colorama import Fore, Style, init
import sys
from concurrent.futures import ThreadPoolExecutor
import IPv4
from ICMP import ICMP, ICMPType
import UDP
import TCP
import DNS
import HTTP
import signal
import random
from utils import Utils
import Ethernet
import os
import psutil


init(autoreset=True)

class PacketTools:
    famous_ports = {80, 443, 21, 22, 23, 25, 53, 110, 143, 161, 194, 389, 443, 465, 514, 587, 636, 993, 995}
    
    def __init__(self):
        # abort if not on linux
        if os.name != "posix":
            print("This program is only supported on Linux.")
            sys.exit(1)
        
        # abort if not root
        if os.geteuid() != 0:
            print("Root privileges are required to run this program.")
            sys.exit(1)
        
        self.source_ipv4_address = "172.18.121.202"#socket.gethostbyname(socket.gethostname())
        self.interface = "eth0"
        # automatcally find MAC address
        self.source_MAC = "00:15:5d:69:b4:e5"
        self.dest_MAC = "00:15:5d:ac:5f:57"
        self.source_port = random.randint(1024, 2**16 - 1)
        self.deafult_ttl = 64
        
        # Increase process priority
        os.nice(-20)  # -20 is the highest priority, adjust as needed

        # Force process to stay on the same core
        p = psutil.Process(os.getpid())
        p.cpu_affinity([0])  # Pin to core 0, adjust as needed

    @staticmethod
    def set_thread_affinity():
        p = psutil.Process(os.getpid())
        p.cpu_affinity([0])
        
    def domain_to_ipv4(self, domain: str, dns_server: str = "8.8.8.8", dest_port: int = 53):
        source_port = random.randint(1024, 2**16 - 1)
        
        DNS_client = DNS.DNS()
        DNS_query = DNS_client.build_packet(domain, DNS.QueryType.A)
        
        udp_packet = UDP.UDPPacket(self.source_ipv4_address, dns_server, source_port, dest_port)
        udp_packet = udp_packet.build_packet(payload=DNS_query)

        ip_header = IPv4.IPHeader(self.source_ipv4_address, dns_server, IPv4.IPProtocol.UDP)
        ip_packet = IPv4.IPPacket(ip_header, udp_packet).build_packet()
    
        ethernet_frame = Ethernet.EthernetFrame(self.source_MAC, self.dest_MAC, ip_packet,
                                                Ethernet.EthernetType.IPv4, use_software_crc=False).build_frame()
    
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
            s.bind((self.interface, 0))
            s.send(ethernet_frame)
    
            try:
                response = s.recv(65535)
                print("Received response from DNS server.")
                #print("Raw DNS Response:", response[42:].hex())
                dns_response = response[42:]
                ipv4_address = DNS_client.parse_packet(dns_response)
                return ipv4_address
    
            except socket.timeout:
                print("Request timed out.")
                return None
    
    def is_online(self, host, timeout=2):
        # check ping
        is_online = False
        
        with ICMP._create_socket() as sock:
            ICMP.send_packet(self.source_ipv4_address, host, icmp_type=ICMPType.ECHO_REQUEST, my_socket=sock, send_time=True)
            
            try:
                res = ICMP.listen_for_reply(timeout=timeout, my_socket=sock)
                print(res)
                if res:
                    is_online = True
            
            # socket timeout
            except socket.timeout:
                pass
        
        # check famous ports
        with ThreadPoolExecutor(3) as executor:
            # scan TCP and UDP
            futures = [executor.submit(self.scan_port, host, port, mode="TCP") for port in self.famous_ports]
            futures += [executor.submit(self.scan_port, host, port, mode="UDP") for port in self.famous_ports]
            result = [future.result()["port_status"] for future in futures]
            is_online = is_online or any(result)
        
        return is_online
    
    def scan_port(self, host, port, mode="TCP", timeout=2, verbose=True):
        assert mode in ["TCP", "UDP"]
        port_status = None
        source_port = random.randint(1024, 2**16 - 1)
        if mode == "TCP":
            tcp_conn = TCP.TCPConnection(self.source_MAC, self.dest_MAC, self.source_ipv4_address,
                                         host, source_port, port, self.interface)
            tcp_conn.verbose = True
            
            port_status, delay = tcp_conn.is_port_open_stealth(port_timeout=timeout, socket_timeout=timeout)
        
        elif mode == "UDP":
            udp_packet = UDP.UDPPacket(self.source_ipv4_address, host, source_port, port).build_packet(payload=b"")
            ip_header = IPv4.IPHeader(self.source_ipv4_address, host, IPv4.IPProtocol.UDP)
            ip_packet = IPv4.IPPacket(ip_header, udp_packet).build_packet()
            ethernet_frame = Ethernet.EthernetFrame(self.source_MAC, self.dest_MAC, ip_packet,
                                                    Ethernet.EthernetType.IPv4, use_software_crc=False)
            ethernet_frame = ethernet_frame.build_frame()

            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as s:
                # set timeout
                s.settimeout(timeout)
                s.bind((self.interface, 0))
                start_time = Utils.get_current_time()
                s.send(ethernet_frame)
                delay = None

                try:
                    while Utils.get_current_time() - start_time < timeout:
                        response = s.recv(1024)
                        IPv4_packet = IPv4.IPHeader.from_bytes(response[14: 34])
                        if IPv4_packet.source_ip != host or IPv4_packet.destination_ip != self.source_ipv4_address:
                            continue
    
                        # Check if response is ICMP Port Unreachable
                        if IPv4_packet.protocol == IPv4.IPProtocol.ICMP.value:
                            port_status = False  # Port is closed
                            delay = (Utils.get_current_time() - start_time) * 1000
                            break
                        
                except socket.timeout:
                    port_status = None  # Port is filtered/open (uncertain)
                    delay = None
        
        try:
            possible_service = socket.getservbyport(port)
            host_name = socket.gethostbyaddr(host)
        
        except Exception:
            possible_service = None
            host_name = None
        
        return {"port_number": port, "port_status": port_status, "latency": delay,
                "possible_service": possible_service, "host_name": host_name, "mode": mode}

    
    def calc_average_latency(self, host, port, n=20, mode="TCP"): 
        assert mode in ["TCP", "UDP"]       
        assert port >= 0 and port <= 2**16
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.threaded_scan_port, host, port, mode) for i in range(n)]
            delays = [future.result()["latency"] for future in futures]
            delays = list(filter(lambda x: x is not None, delays))
            
        average_delay = sum(delays) / len(delays) if delays else None
        return average_delay

    def threaded_scan_port(self, host, port, mode, verbose=False):
        self.set_thread_affinity()
        return self.scan_port(host, port, mode, verbose=False)
    
    def scan_port_range(self, host, start_port=1, end_port=1024, mode="ALL"):
        assert mode in ["TCP", "UDP", "ALL"]
        assert start_port >= 0 and start_port <= 2**16
        assert end_port >= 0 and end_port <= 2**16
        
        with ThreadPoolExecutor() as executor:
            if mode == "ALL":
                # Submit TCP scan jobs
                print("Scanning TCP ports...")
                tcp_futures = [executor.submit(self.scan_port, host, port, "TCP", verbose=False) 
                                for port in range(start_port, end_port + 1)]
                # Submit UDP scan jobs  
                print("Scanning UDP ports...")
                udp_futures = [executor.submit(self.scan_port, host, port, "UDP", verbose=False)
                                for port in range(start_port, end_port + 1)]
                # Combine results
                tcp_results = [future.result()["port_status"] for future in tcp_futures]
                udp_results = [future.result()["port_status"] for future in udp_futures]
                return {"TCP": tcp_results, "UDP": udp_results}
            else:
                print(f"Scanning {mode} ports...")
                futures = [executor.submit(self.scan_port, host, port, mode, verbose=False) 
                            for port in range(start_port, end_port + 1)]
                result = [future.result() for future in futures]
                return result
    
    
    def send_http_req(self, host, request, port=80):
        source_port = random.randint(1024, 2**16 - 1)
        tcp_conn = TCP.TCPConnection(self.source_MAC, self.dest_MAC, self.source_ipv4_address,
                                     host, source_port, port, self.interface)
        tcp_conn.verbose = False
        
        try:
            tcp_conn.open(wait_until_established=True)
        
        except Exception as e:
            print(f"Failed opening connection to {host}: {e}")
            return
        
        try:
            tcp_conn.send(bytes(request, encoding="utf-8"))
            response = tcp_conn.receive()
        
        except Exception as e:
            print(f"Failed sending data to {host}: {e}")
            tcp_conn.abort()
        
        # try:
        #     tcp_conn.close()
        
        # except Exception as e:
        #     print(f"Failed closing connection to {host}: {e}")
        #     tcp_conn.abort()
        
        return response.decode()
    
    def send_http_get(self, user_name, host, port=80):
        request_text = f"GET /{user_name} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        res = self.send_http_req(host, request_text, port)
        return res

    def send_http_post(self, user_name, age, host, port=80):
        request_text = f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\nContent-Length: {len(user_name) + len(str(age)) + 1}\r\n\r\n{user_name} {age}"
        res = self.send_http_req(host, request_text, port)
        return res

    def send_http_delete(self, user_name, host, port=80):
        request_text = f"DELETE /{user_name} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        res = self.send_http_req(host, request_text, port)
        return res
    
    def ping(self, host, count=10, timeout=1, delay=1, payload_size_bytes=32):
        ICMP.ping(self.source_ipv4_address, host, count, timeout, delay, payload_size_bytes)
    
    def traceroute(self, host, max_hops=30, timeout=1):
        ICMP.traceroute(self.source_ipv4_address, host, max_hops, timeout)
