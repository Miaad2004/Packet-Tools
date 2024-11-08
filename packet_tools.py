import socket
import time
import argparse
import argparse
from colorama import Fore, Style, init
import sys
from concurrent.futures import ThreadPoolExecutor
import IPv4
from ICMP import ICMP, ICMPType
import UDP
import TCP
import DNS
import random
from utils import Utils
import Ethernet
import os
import psutil


init(autoreset=True)

class PacketTools:
    famous_ports = {80, 443, 21, 22, 23, 25, 53, 110, 143, 161, 194, 389, 443, 465, 514, 587, 636, 993, 995, 8080}
    
    def __init__(self, source_ipv4_address, interface, source_MAC, dest_MAC, default_ttl=64):
        # abort if not on linux
        if os.name != "posix":
            print("This program is only supported on Linux.")
            sys.exit(1)
        
        # abort if not root
        if os.geteuid() != 0:
            print("Root privileges are required to run this program.")
            sys.exit(1)
        
        self.source_ipv4_address = source_ipv4_address
        self.interface = interface
        self.source_MAC = source_MAC
        self.dest_MAC =  dest_MAC
        self.source_port = random.randint(1024, 2**16 - 1)
        self.deafult_ttl = default_ttl
        
        # Increase process priority
        os.nice(-20)  

        # Force process to stay on the same core
        p = psutil.Process(os.getpid())
        p.cpu_affinity([0])  # Pin to core 0

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
        
        if is_online:
            return is_online
        
        # check famous ports
        with ThreadPoolExecutor() as executor:
            # scan TCP and UDP
            futures = [executor.submit(self.scan_port, host, port, mode="TCP") for port in self.famous_ports]
            futures += [executor.submit(self.scan_port, host, port, mode="UDP") for port in self.famous_ports]
            result = [future.result()["port_status"] for future in futures]
            is_online = is_online or any(result)
        
        return is_online
    
    def scan_port(self, host, port, mode="TCP", timeout=2, verbose=False, udp_payload_size=16):
        assert mode in ["TCP", "UDP"]
        port_status = None
        source_port = random.randint(1024, 2**16 - 1)
        if mode == "TCP":
            tcp_conn = TCP.TCPConnection(self.source_MAC, self.dest_MAC, self.source_ipv4_address,
                                         host, source_port, port, self.interface)
            tcp_conn.verbose = verbose
            
            port_status, delay = tcp_conn.is_port_open_stealth(port_timeout=timeout, socket_timeout=timeout)
        
        elif mode == "UDP":
            udp_packet = UDP.UDPPacket(self.source_ipv4_address, host, source_port, port).build_packet(payload=os.urandom(udp_payload_size))
            ip_header = IPv4.IPHeader(self.source_ipv4_address, host, IPv4.IPProtocol.UDP)
            ip_packet = IPv4.IPPacket(ip_header, udp_packet).build_packet()
            ethernet_frame = Ethernet.EthernetFrame(self.source_MAC, self.dest_MAC, ip_packet,
                                                    Ethernet.EthernetType.IPv4, use_software_crc=False)
            ethernet_frame = ethernet_frame.build_frame()

            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as s:
                # set timeout
                s.settimeout(timeout + 1)
                s.bind((self.interface, 0))
                start_time = Utils.get_current_time()
                s.send(ethernet_frame)
                delay = None

                try:
                    while Utils.get_current_time() - start_time < timeout:
                        response = s.recv(1024)
                        received_time = Utils.get_current_time()
                        
                        IPv4_packet = IPv4.IPHeader.from_bytes(response[14: 34])
                        if IPv4_packet.source_ip != host or IPv4_packet.destination_ip != self.source_ipv4_address:
                            continue
                        
                        # Check if response is ICMP Port Unreachable
                        if IPv4_packet.protocol == IPv4.IPProtocol.ICMP.value:
                            port_status = False  # Port is closed
                            delay = (received_time - start_time) * 1000
                            break
                        
                        # Check if response is UDP
                        if IPv4_packet.protocol == IPv4.IPProtocol.UDP.value:
                            UDP_packet, payload = UDP.UDPPacket.from_bytes(response[34:])
                            if UDP_packet.source_port == port:
                                port_status = True
                                delay = (received_time - start_time) * 1000
                                break
                        
                        
                except socket.timeout:
                    port_status = None  # Port is filtered/open (uncertain)
                    delay = None
        
        try:
            possible_service = socket.getservbyport(port)
        
        except Exception as e:
            possible_service = None
        
        return {"port_number": port, "port_status": port_status, "latency": delay,
                "possible_service": possible_service, "mode": mode}

    
    def calc_average_latency(self, host, port, n=20, mode="TCP"): 
        assert mode in ["TCP", "UDP"]       
        assert port >= 0 and port <= 2**16
        
        with ThreadPoolExecutor(5) as executor:
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
                tcp_results = [future.result() for future in tcp_futures]
                udp_results = [future.result() for future in udp_futures]
                results = tcp_results + udp_results
                
                return results
            
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
        tcp_conn.abort()
        
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
    
    def resolve_host(self, host):
        try:
            # Check if host is already an IP address
            socket.inet_aton(host)
            return host
        
        except OSError:
            try:
                return self.domain_to_ipv4(host)
            
            except Exception:
                return None


class CLI:
    def __init__(self, source_ipv4_address, interface, source_MAC, dest_MAC):
        self.packet_tools = PacketTools(source_ipv4_address, interface, source_MAC, dest_MAC)
    
    def execute_command(self, args):
        try:
            # Resolve host to IP if necessary
            if hasattr(args, 'host'):
                resolved_host = self.packet_tools.resolve_host(args.host)
                if not resolved_host:
                    print(f"{Fore.RED}Unable to resolve host {args.host}")

            if args.command in ['domain_to_ipv4', 'd2ip']:
                print(f"{Fore.YELLOW}Resolving domain {args.domain}...")
                ip_address = self.packet_tools.domain_to_ipv4(args.domain, args.dns_server, args.dest_port)
                if ip_address:
                    print(f"{Fore.GREEN}Domain {args.domain} resolved to {ip_address}")
                else:
                    print(f"{Fore.RED}Failed to resolve domain {args.domain}")

            elif args.command in ['is_online', 'io']:
                print(f"{Fore.YELLOW}Checking if host {args.host} is online...")
                online = self.packet_tools.is_online(resolved_host, args.timeout)
                if online:
                    print(f"{Fore.GREEN}Host {resolved_host} is online")
                else:
                    print(f"{Fore.RED}Host {resolved_host} is offline or unreachable")

            elif args.command in ['scan_port', 'sp']:
                print(f"{Fore.YELLOW}Scanning port {args.port} on host {resolved_host} using {args.mode}...")
                result = self.packet_tools.scan_port(resolved_host, args.port, args.mode, args.timeout)
                if result['port_status']:
                    status = f"{Fore.GREEN}Open"
                elif result['port_status'] is False:
                    status = f"{Fore.RED}Closed"
                else:
                    status = f"{Fore.YELLOW}Filtered/Unknown"
                    
                print(f"Port {result['port_number']}/{result['mode']} is {status}")
                
                if result['possible_service']:
                    print(f"Possible service: {result['possible_service']}")
                    
                if result['latency'] is not None:
                    print(f"Latency: {result['latency']: .3f} ms")
                    
            elif args.command in ['calc_average_latency', 'cal']:
                print(f"{Fore.YELLOW}Calculating average latency to port {args.port} on host {args.host}...")
                avg_latency = self.packet_tools.calc_average_latency(resolved_host, args.port, args.n, args.mode)
                if avg_latency:
                    print(f"{Fore.GREEN}Average latency: {avg_latency:.3f} ms")
                
                else:
                    print(f"{Fore.RED}Host {args.host} or port {args.port} is unreachable")

            elif args.command in ['scan_port_range', 'spr']:
                print(f"{Fore.YELLOW}Scanning ports {args.start_port}-{args.end_port} on host {resolved_host} using {args.mode}...")
                results = self.packet_tools.scan_port_range(resolved_host, args.start_port, args.end_port, args.mode)
                for result in results:
                    if result['port_status']:
                        status = f"{Fore.GREEN}Open"
                    elif result['port_status'] is False:
                        status = f"{Fore.RED}Closed"
                        continue
                    
                    else:
                        status = f"{Fore.YELLOW}Filtered/Unknown"
                        continue
                        
                    print(f"Port {result['port_number']}/{result['mode']} is {status}")
                    if result['possible_service']:
                        print(f"Possible service: {result['possible_service']}")
                        
                    if result['latency'] is not None:
                        print(f"Latency: {result['latency']:.3f} ms")

                    print("")

            elif args.command in ['send_http_get', 'get']:
                print(f"{Fore.YELLOW}Sending HTTP GET request to {args.host}:{args.port}...")
                response = self.packet_tools.send_http_get(args.user_name, resolved_host, args.port)
                print(f"{Fore.GREEN}Response:\n{response}")

            elif args.command in ['send_http_post', 'post']:
                print(f"{Fore.YELLOW}Sending HTTP POST request to {args.host}:{args.port}...")
                response = self.packet_tools.send_http_post(args.user_name, args.age, resolved_host, args.port)
                print(f"{Fore.GREEN}Response:\n{response}")

            elif args.command in ['send_http_delete', 'delete']:
                print(f"{Fore.YELLOW}Sending HTTP DELETE request to {args.host}:{args.port}...")
                response = self.packet_tools.send_http_delete(args.user_name, resolved_host, args.port)
                print(f"{Fore.GREEN}Response:\n{response}")

            elif args.command in ['ping', 'p']:
                print(f"{Fore.YELLOW}Pinging {args.host} with {args.count} packets...")
                self.packet_tools.ping(resolved_host, args.count, args.timeout, args.delay, args.size)

            elif args.command in ['traceroute', 'tr']:
                print(f"{Fore.YELLOW}Tracing route to {args.host} with max {args.max_hops} hops...")
                self.packet_tools.traceroute(resolved_host, args.max_hops, args.timeout)

        except Exception as e:
            print(f"{Fore.RED}An error occurred: {e}")

    def run(self):
        version = "1.0"
        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Fore.GREEN}PacketTools CLI Version {version}")
        print(f"Scan started at {start_time}\n")

        parser = argparse.ArgumentParser(
            description='PacketTools Command Line Interface',
            formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-i', '--interactive', action='store_true', help='Enter interactive mode')
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # domain_to_ipv4 command
        parser_domain = subparsers.add_parser('domain_to_ipv4', aliases=['d2ip'], help='Resolve domain to IPv4 address')
        parser_domain.add_argument('domain', help='Domain name to resolve')
        parser_domain.add_argument('--dns-server', default='8.8.8.8', help='DNS server to use')
        parser_domain.add_argument('--dest-port', type=int, default=53, help='Destination port (default: 53)')

        # is_online command
        parser_online = subparsers.add_parser('is_online', aliases=['io'], help='Check if host is online')
        parser_online.add_argument('host', help='Host to check')
        parser_online.add_argument('--timeout', type=int, default=2, help='Timeout in seconds')

        # scan_port command
        parser_scan_port = subparsers.add_parser('scan_port', aliases=['sp'], help='Scan a specific port on a host')
        parser_scan_port.add_argument('host', help='Host to scan')
        parser_scan_port.add_argument('port', type=int, help='Port number to scan')
        parser_scan_port.add_argument('--mode', choices=['TCP', 'UDP'], default='TCP', help='Protocol to use')
        parser_scan_port.add_argument('--timeout', type=int, default=2, help='Timeout in seconds')

        # calc_average_latency command
        parser_latency = subparsers.add_parser('calc_average_latency', aliases=['cal'], help='Calculate average latency to a port')
        parser_latency.add_argument('host', help='Host to measure')
        parser_latency.add_argument('port', type=int, help='Port number')
        parser_latency.add_argument('-n', type=int, default=100, help='Number of samples')
        parser_latency.add_argument('--mode', choices=['TCP', 'UDP'], default='TCP', help='Protocol to use')

        # scan_port_range command
        parser_port_range = subparsers.add_parser('scan_port_range', aliases=['spr'], help='Scan a range of ports')
        parser_port_range.add_argument('host', help='Host to scan')
        parser_port_range.add_argument('--start-port', type=int, default=1, help='Start of port range')
        parser_port_range.add_argument('--end-port', type=int, default=1024, help='End of port range')
        parser_port_range.add_argument('--mode', choices=['TCP', 'UDP', 'ALL'], default='ALL', help='Protocol to use')

        # send_http_get command
        parser_http_get = subparsers.add_parser('send_http_get', aliases=['get'], help='Send HTTP GET request')
        parser_http_get.add_argument('user_name', help='User name')
        parser_http_get.add_argument('host', help='Host to send request to')
        parser_http_get.add_argument('--port', type=int, default=80, help='Port number (default: 80)')

        # send_http_post command
        parser_http_post = subparsers.add_parser('send_http_post', aliases=['post'], help='Send HTTP POST request')
        parser_http_post.add_argument('user_name', help='User name')
        parser_http_post.add_argument('age', help='Age')
        parser_http_post.add_argument('host', help='Host to send request to')
        parser_http_post.add_argument('--port', type=int, default=80, help='Port number (default: 80)')

        # send_http_delete command
        parser_http_delete = subparsers.add_parser('send_http_delete', aliases=['delete'], help='Send HTTP DELETE request')
        parser_http_delete.add_argument('user_name', help='User name')
        parser_http_delete.add_argument('host', help='Host to send request to')
        parser_http_delete.add_argument('--port', type=int, default=80, help='Port number (default: 80)')

        # ping command
        parser_ping = subparsers.add_parser('ping', aliases=['p'], help='Ping a host')
        parser_ping.add_argument('host', help='Host to ping')
        parser_ping.add_argument('-c', '--count', type=int, default=10, help='Number of packets to send')
        parser_ping.add_argument('--timeout', type=int, default=1, help='Timeout in seconds')
        parser_ping.add_argument('--delay', type=int, default=1, help='Delay between packets')
        parser_ping.add_argument('--size', type=int, default=32, help='Payload size in bytes')

        # traceroute command
        parser_traceroute = subparsers.add_parser('traceroute', aliases=['tr'], help='Perform traceroute to a host')
        parser_traceroute.add_argument('host', help='Host to traceroute')
        parser_traceroute.add_argument('--max-hops', type=int, default=30, help='Maximum number of hops')
        parser_traceroute.add_argument('--timeout', type=int, default=1, help='Timeout in seconds')

        # Parse arguments
        args = parser.parse_args()
        
        if args.interactive:
            while True:
                try:
                    user_input = input(f"{Fore.CYAN}PacketTools> {Style.RESET_ALL}")
                    if user_input.lower() in ['exit', 'quit']:
                        break
                    
                    interactive_args = parser.parse_args(user_input.split())
                    self.execute_command(interactive_args)
                    
                except SystemExit:
                    pass  # Ignore argparse exit
        else:
            if not args.command:
                parser.print_help()
                sys.exit(1)
                
            self.execute_command(args)


        end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Fore.GREEN}Operation completed at {end_time}")


if __name__ == '__main__':
        source_ipv4_address = "172.18.121.202"
        interface = "eth0"
        source_MAC = "00:15:5d:69:b4:e5"
        dest_MAC = "00:15:5d:ac:5f:57"
        
        cli = CLI(source_ipv4_address, interface, source_MAC, dest_MAC)
        cli.run()

    
    