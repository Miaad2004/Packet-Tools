import socket
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ICMP, IP, sr1

class NetworkMapper:
    def __init__(self):
        pass 
        self.conn_timeout = 0
    
    def send_arp():
        pass
    
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
        response = sr1(packet, timeout=self.conn_timeout, verbose=False)
        
        return any(TCP_result + UDP_result + [response])

    
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
    

 
 