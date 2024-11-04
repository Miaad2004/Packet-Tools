import socket
import json

class HTTPClient:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port

    def send_get_request(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            request_line = f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
            sock.sendall(request_line.encode('utf-8'))
            response = self.receive_response(sock)
            print("GET Response:\n", response)

    def send_post_request(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            json_data = json.dumps(data)
            request_line = f"POST / HTTP/1.1\r\nHost: {self.host}\r\n"
            request_line += f"Content-Type: application/json\r\n"
            request_line += f"Content-Length: {len(json_data)}\r\n\r\n"
            request_line += json_data
            sock.sendall(request_line.encode('utf-8'))
            response = self.receive_response(sock)
            print("POST Response:\n", response)

    def send_delete_request(self, item_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            request_line = f"DELETE /{item_id} HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
            sock.sendall(request_line.encode('utf-8'))
            response = self.receive_response(sock)
            print("DELETE Response:\n", response)

    def receive_response(self, sock):
        response = ""
        while True:
            part = sock.recv(4096).decode('utf-8')
            response += part
            if len(part) < 4096:
                break
        return response

if __name__ == '__main__':
    client = HTTPClient()

    # Send a GET request
    client.send_get_request()

    # Send a POST request with data
    client.send_post_request({'name': 'Item 1'})

    # Send a DELETE request (delete the first item, index 0)
    client.send_delete_request(0)

    # Send a GET request again to see the updated state
    client.send_get_request()
