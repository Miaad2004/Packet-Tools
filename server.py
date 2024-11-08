import socket
import threading

users = {
    'user1': {'name': 'Alice', 'age': 30},
    'user2': {'name': 'Bob', 'age': 25},
    'user3': {'name': 'Charlie', 'age': 35},
}

def handle_get_request(request):
    request_parts = request.split()
    if len(request_parts) >= 2:
        user_id = request_parts[1].lower().lstrip('/').strip()
        print(f"User Requested: {user_id}")
        if user_id in users:
            user_info = users[user_id]
            response = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{user_info}"
        else:
            response = "HTTP/1.1 404 Not Found\n\nUser not found"
    else:
        response = "HTTP/1.1 400 Bad Request\n\nInvalid GET request"
    return response

def handle_post_request(request):
    body = request.split('\r\n\r\n', 1)[1]
    name_age = body.strip().split(' ')
    if len(name_age) >= 2:
        name = name_age[0].lower().strip()
        age = name_age[1].lower().strip()
        users[f'user{len(users)+1}'] = {'name': name, 'age': int(age)}
        response = "HTTP/1.1 200 OK\n\nUser data updated"
        print(f"New user added: {name}, {age}")
    else:
        response = "HTTP/1.1 400 Bad Request\n\nInvalid POST data"
    return response

def handle_delete_request(request):
    request_parts = request.split()
    if len(request_parts) >= 2:
        user_id = request_parts[1].lstrip('/').strip().lower()
        if user_id in users:
            del users[user_id]
            response = "HTTP/1.1 200 OK\n\nUser deleted"
            print(f"User deleted: {user_id}")
            
        else:
            response = "HTTP/1.1 404 Not Found\n\nUser not found"
            
    else:
        response = "HTTP/1.1 400 Bad Request\n\nInvalid DELETE request"
    return response

def handle_client(client_socket):
    request = client_socket.recv(1024).decode()
    if "GET" in request:
        response = handle_get_request(request)
    elif "POST" in request:
        response = handle_post_request(request)
    elif "DELETE" in request:
        response = handle_delete_request(request)
    else:
        response = "HTTP/1.1 400 Bad Request\n\nInvalid request"
    client_socket.sendall(response.encode())
    client_socket.close()

def main():
    host = '192.168.1.5'
    port = 8080
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server is listening on http://{host}:{port}")
    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == '__main__':
    main()