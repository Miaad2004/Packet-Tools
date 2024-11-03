import socket
import os
import struct
import time
from enum import Enum
import subprocess
import platform
import atexit
import IP

class ICMPType(Enum):
    ECHO_REPLY = 0  # Echo reply (used to ping)
    DEST_UNREACHABLE = 3  # Destination Unreachable
    SOURCE_QUENCH = 4  # Source Quench (deprecated)
    REDIRECT_MESSAGE = 5  # Redirect Message
    ECHO_REQUEST = 8  # Echo request (used to ping)
    ROUTER_ADVERTISEMENT = 9  # Router Advertisement
    ROUTER_SOLICITATION = 10  # Router Solicitation
    TIME_EXCEEDED = 11  # Time to live (TTL) expired in transit
    PARAMETER_PROBLEM = 12  # Parameter Problem: Bad IP header
    TIMESTAMP = 13  # Timestamp
