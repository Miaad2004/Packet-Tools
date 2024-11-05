import time

class Utils:
    @staticmethod
    def calculate_checksum(packet_header):
        # pad even packets
        if len(packet_header) % 2 == 1:
            packet_header += b'\x00'     # add a zero byte
        
        checksum = 0
        for i in range(0, len(packet_header), 2):
            # add 2 bytes by 2 bytes
            checksum += (packet_header[i] << 8) + packet_header[i + 1]
            carry = checksum >> 16
            
            # mask to 16 bits and wrap around carry
            checksum = (checksum & 0xFFFF) + carry

        # one's complement and mask to 16 bits
        checksum = ~checksum & 0xFFFF
        return checksum
    
    @staticmethod
    def ip_to_bytes(ipv4: str) -> bytes:
        parts = map(int, ipv4.split("."))
        return bytes(parts)
    
    @staticmethod
    def bytes_to_ip(ipv4_bytes: bytes) -> str:
        return ".".join(map(str, ipv4_bytes))
    
    @staticmethod
    def mac_to_bytes(mac: str) -> bytes:
        parts = map(lambda x: int(x, 16), mac.split(":"))
        return bytes(parts)
    
    @staticmethod
    def bytes_to_mac(mac_bytes: bytes) -> str:
        return ":".join(map(lambda x: format(x, "02x"), mac_bytes))
    
    @staticmethod
    def get_current_time():
        return time.perf_counter()