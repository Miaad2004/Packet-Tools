import socket
import time
import argparse
import threading
import argparse
from art import text2art
from colorama import Fore, Style, init
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ICMP, IP, sr1

init(autoreset=True)

class NetworkMapper:
    def __init__(self):
        pass 
        self.conn_timeout = 0
    
    def send_arp():
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
        
        hosts = []
        for element in answered_list:
            hosts.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
        return hosts
    
    def send_icmp(host,  icmp_type=0, icmp_code=0, identifier=1, sequence=1, payload=b''):
        ip_layer = IP(dst=host)
        icmp_packet = ICMP(type=icmp_type, code=icmp_code, id=identifier, seq=sequence) / payload
        packet = ip_layer / icmp_packet
        response = sr1(packet, timeout=2, verbose=False)
        return response
    
    def is_online(self, host):
        # check for ports from 1 to 1024
        TCP_result = self.scan_port_range(host, start_port=0, end_port=1024, mode="TCP")
        UDP_result = self.scan_port_range(host, start_port=0, end_port=1024, mode="UDP")
        
        # check ICMP
        packet = IP(dst=host)/ICMP()
        ping_response = sr1(packet, timeout=self.conn_timeout, verbose=False)
        
        return any(TCP_result + UDP_result + [ping_response])

    
    def scan_port(self, host, port, mode="TCP"):
        assert mode in ["TCP", "UDP"]
        assert port >= 0 and port <= 2**16
        
        socket_type = socket.SOCK_STREAM if mode == "TCP" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, socket_type) as s:
            s.settimeout(self.conn_timeout)
            start_time = time.time()
            is_open = s.connect_ex((host, port)) == 0
            latency = time.time() - start_time if is_open else None
        
        return{"port_number": port, "port_status": is_open, "latency": latency}
    
    def calc_average_latency(self, host, port, n=100, mode="TCP"): 
        assert mode in ["TCP", "UDP"]       
        assert port >= 0 and port <= 2**16
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.scan_port, host, port, mode) for i in range(n)]
            delays = [future.result()["latency"] for future in futures]
            filter(delays, lambda x: x is not None)
            
        average_delay = sum(delays) / len(delays)
        return average_delay
    
    def scan_port_range(self, host, start_port=0, end_port=1024, mode="TCP"):
        assert mode in ["TCP", "UDP"] 
        assert start_port >= 0 and start_port <= 2**16
        assert end_port >= 0 and end_port <= 2**16
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.scan_port, host, port, mode) for port in range(start_port, end_port + 1)]
            result = [future.result()["port_status"] for future in futures]
            
        return result
    
    def send_http_get():
        pass
    
    def send_http_post():
        pass
    
    def send_http_delete():
        pass
    
def main():
    # Display ASCII Art Title with cyan color
    title_art = text2art("Network Mapper")
    print(Fore.CYAN + title_art)
    
    # Argument parser setup
    parser = argparse.ArgumentParser(
        description="Network Mapper - A simple command-line tool for scanning ports and network mapping, similar to nmap"
    )
    
    parser.add_argument("host", help="Specify the target host IP address or domain name")
    
    parser.add_argument(
        "-p", "--port", type=int, nargs=2, metavar=("start_port", "end_port"),
        help="Specify the port range to scan, e.g., -p 0 1024"
    )
    
    parser.add_argument(
        "-m", "--mode", choices=["TCP", "UDP"], default="TCP",
        help="Select the scanning mode, either TCP or UDP (default is TCP)"
    )
    
    parser.add_argument(
        "-t", "--timeout", type=int, default=2,
        help="Set the timeout for each connection attempt in seconds (default is 2)"
    )
    
    parser.add_argument(
        "-l", "--latency", action="store_true",
        help="Calculate average latency for the specified port"
    )

    args = parser.parse_args()
    
    nm = NetworkMapper()
    nm.conn_timeout = args.timeout
    
    # Display port scan results
    if args.port:
        start_port, end_port = args.port
        print(Fore.BLUE + f"Scanning ports {start_port}-{end_port} on host {args.host} using {args.mode} mode...")
        results = nm.scan_port_range(args.host, start_port, end_port, mode=args.mode)
        for port, status in enumerate(results, start=start_port):
            status_str = "Open" if status else "Closed"
            color = Fore.GREEN if status else Fore.RED
            print(color + f"Port {port}: {status_str}")

    # Calculate average latency if requested
    if args.latency and args.port:
        start_port, end_port = args.port
        print(Fore.MAGENTA + f"\nCalculating average latency for port {start_port} on host {args.host} using {args.mode} mode...")
        latency = nm.calc_average_latency(args.host, start_port, mode=args.mode)
        print(Fore.YELLOW + f"Average Latency for port {start_port}: {latency:.2f} seconds")

if __name__ == "__main__":
    main()