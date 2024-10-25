import socket
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

class NetworkMapper:
    def __init__(self):
        pass 
        self.conn_timeout = 
    
    @staticmethod
    def is_online(host):
        # Should check icmp + ports 1 to 1024
        pass
    
    def scan_port(self, host, port, mode="TCP"):
        assert mode in ["TCP", "UDP"]
        assert port >= 0 and port <= 2**16
        
        socket_type = socket.SOCK_STREAM if mode == "TCP" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, socket_type) as s:
            s.settimeout(self.conn_timeout)
            start_time = time.time()
            is_open = s.connect_ex((host, port)) == 0
            latency = time.time() - start_time if is_open else None
        
        return [is_open, latency]
    
    def calc_average_latency(self, host, port, n=100, mode="TCP"):        
        # scans a single port if open returns the latencies
        pass
    
    def scan_port_range():
        # scans a range of ports using mutithreading (and calculates latencies)
        pass
    
    def send_http_get():
        pass
    
    def send_http_post():
        pass
    
    def send_http_delete():
        pass
    
    
 