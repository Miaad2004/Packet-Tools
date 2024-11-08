import socket

def udp_server(listen_ip, listen_port):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    server_address = (listen_ip, listen_port)
    print(f'Starting up on {server_address[0]} port {server_address[1]}')
    sock.bind(server_address)
    
    while True:
        print('\nWaiting to receive message')
        data, address = sock.recvfrom(4096)
        
        print(f'Received {len(data)} bytes from {address}')
        print(data)
        
        if data:
            sent = sock.sendto(data, address)
            print(f'Sent {sent} bytes back to {address}')

if __name__ == '__main__':
    udp_server("127.0.0.1", 57)  