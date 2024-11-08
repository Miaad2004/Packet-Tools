# PacketTools

PacketTools is a Python-based network utility tool, featuring a scratch implementation of TCP, UDP, ICMP, DNS, and IPv4 protocols. It allows users to perform port scanning, latency measurement, DNS resolution, HTTP requests, ping, and traceroute.

## Features

- **Port Scanning**: Scan specific ports or a range of ports using TCP or UDP.
- **Latency Measurement**: Calculate the average latency to a specific port.
- **DNS Resolution**: Resolve domain names to IPv4 addresses.
- **HTTP Requests**: Send HTTP GET, POST, and DELETE requests.
- **Ping**: Check the reachability of a host.
- **Traceroute**: Trace the route to a host.

## Requirements

- Python 3.x
- Linux operating system
- Root privileges

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/Miaad2004/Packet-Tools
   cd packettools
   ```

2. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface (CLI)

PacketTools provides a CLI for executing various network tasks. Below are some examples of how to use the CLI.

1. **Resolve Domain to IPv4**:

   ```sh
   python packet_tools.py domain_to_ipv4 example.com
   ```

2. **Check if Host is Online**:

   ```sh
   python packet_tools.py is_online 192.168.1.1
   ```

3. **Scan a Specific Port**:

   ```sh
   python packet_tools.py scan_port 192.168.1.1 80 --mode TCP
   ```

4. **Calculate Average Latency**:

   ```sh
   python packet_tools.py calc_average_latency 192.168.1.1 80 -n 20 --mode TCP
   ```

5. **Scan a Range of Ports**:

   ```sh
   python packet_tools.py scan_port_range 192.168.1.1 --start-port 1 --end-port 1024 --mode ALL
   ```

6. **Send HTTP GET Request**:

   ```sh
   python packet_tools.py send_http_get username example.com --port 80
   ```

7. **Ping a Host**:

   ```sh
   python packet_tools.py ping 192.168.1.1 -c 10 --timeout 1 --delay 1 --size 32
   ```

8. **Perform Traceroute**:
   ```sh
   python packet_tools.py traceroute 192.168.1.1 --max-hops 30 --timeout 1
   ```

### Interactive Mode

To enter interactive mode, use the `-i` or `--interactive` flag:

```sh
python packet_tools.py -i
```

In interactive mode, you can type commands directly into the CLI prompt.
