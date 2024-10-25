import socket
import time
import argparse
import threading

class NetworkMapper:
    def __init__(self):
        pass 
        self.ttl = 0.5
    
    @staticmethod
    def is_online(host):
        # Should check icmp + ports 1 to 1024
        pass
    
    def scan_port(host, port, result, mode="TCP"):
        assert mode in ["TCP", "UDP"]
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
    
    
 