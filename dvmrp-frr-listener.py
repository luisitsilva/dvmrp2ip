#!/usr/bin/env python3
"""
DVMRP Route Listener and ZAPI injector for FRRouting
Injects DVMRP-learned routes into Zebra so PIM can use them for RPF checks.
"""

import socket
import struct
import logging
import time
import sys
import os
from typing import Optional, Dict

# ZAPI Protocol Constants
ZAPI_VERSION = 3
ZEBRA_ROUTE_ADD = 9
ZEBRA_ROUTE_DELETE = 10
ZEBRA_HELLO = 19
ZEBRA_REDISTRIBUTE_ADD = 12
ZEBRA_REDISTRIBUTE_DELETE = 13

# Route types (from FRR source: lib/zclient.h)
ZEBRA_ROUTE_KERNEL = 0
ZEBRA_ROUTE_STATIC = 1
ZEBRA_ROUTE_BABEL = 17  # Babel route type
ZEBRA_ROUTE_OSPF = 11   # OSPF route type

# Administrative distance for DVMRP routes (lower is preferred)
DISTANCE_DVMRP = 85

# ZAPI Message Header Format
# struct zclient_header {
#   uint16_t length;
#   uint8_t marker;
#   uint8_t version;
#   uint16_t vrf_id;
#   uint16_t command;
# }
ZAPI_HEADER_FMT = '!HBBHH'
ZAPI_HEADER_SIZE = struct.calcsize(ZAPI_HEADER_FMT)

# AFI constants
AF_INET = 2
AF_INET6 = 10

class ZAPIClient:
    """ Client for the Zebra (ZAPI) protocol """

    def __init__(self, socket_path='/var/run/frr/zserv.api'):
        self.socket_path = socket_path
        self.sock = None
        self.logger = logging.getLogger('zapi-client')

    def connect(self) -> bool:
        """ Connect to Zebra via Unix domain socket """
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            self.logger.info(f"Connected to Zebra at {self.socket_path}")

            # Send HELLO message to register as a client
            self._send_hello()
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Zebra: {e}")
            return False
    
    def _send_message(self, command: int, data: bytes = b'') -> bool:
        """ Send a ZAPI message with proper header """
        length = ZAPI_HEADER_SIZE + len(data)
        header = struct.pack(ZAPI_HEADER_FMT, length, 0xff, ZAPI_VERSION, 0, command)

        try:
            self.sock.send(header + data)
            self.logger.debug(f"Sent message: command={command}, length={length}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            return False

    def _send_hello(self) -> None:
        """ Send ZEBRA_HELLO to register this client """
        # Hello message body: protocol version (uint8), receive buffer size (uint32)
        data = struct.pack('!BI', 2, 4096)    # ZAPI version 2, buffer size
        self._send_message(ZEBRA_HELLO, data)

    def _encode_ipv4_prefix(self, prefix: str, prefixlen: int) -> bytes:
        """ Encode an IPv4 prefix for ZAPI route messages """
        addr_bytes = socket.inet_aton(prefix)
        # Prefix structure: AFI (2 bytes), prefixlen (1 byte), address bytes
        return struct.pack('!HB', AF_INET, prefixlen) + addr_bytes

    def _encode_route(self, prefix: str, prefixlen: int, nexthop: str, metric: int = 20) -> bytes:
        """
        Encode a route message for ZEBRA_ROUTE_ADD
        based on zapi_route structure from FRR
        """
        # Route structure (simplified):
        # - type (1 byte)
        # - instance (2 bytes)
        # - flags (4 bytes)
        # - message (4 bytes)
        # - safi (1 byte)
        # - prefix (variable)
        # - nexthop count (1 byte)
        # - nexthops (variable)
        # - metric (4 bytes)
        # - distance (1 byte)

        route_type = ZEBRA_ROUTE_BABEL  # Use BABEL type for DVMRP routes
        instance = 0
        flags = 0
        message = 0x01  # ZAPI_MESSAGE_NEXTHOP
        safi = 1  # SAFI_UNICAST
 
        # Build prefix
        prefix_bytes = self._encode_ipv4_prefix(prefix, prefixlen)

        # Encode nexthop
        nh_addr = socket.inet_aton(nexthop)
        # Nexthop structure: type (1 byte), AFI (2 bytes), address bytes
        nexthop_bytes = struct.pack('!BH', 1, AF_INET) + nh_addr  # NEXTHOP_TYPE_IPV4 = 1

        # Build full message
        data = struct.pack('!B H I I B', route_type, instance, flags, message, safi)
        data += prefix_bytes
        data += struct.pack('!B', 1)  # nexthop count
        data += nexthop_bytes
        data += struct.pack('!I', metric)  # metric
        data += struct.pack('!B', DISTANCE_DVMRP)  # administrative distance

        return data

    def add_route(self, prefix: str, prefixlen: int, nexthop: str, metric: int = 20) -> bool:
        """ Add a route to Zebra RIB via ZAPI """
        data = self._encode_route(prefix, prefixlen, nexthop, metric)
        return self._send_message(ZEBRA_ROUTE_ADD, data)

    def delete_route(self, prefix: str, prefixlen: int) -> bool:
        """ Delete a route from Zebra RIB """
        data = self._encode_ipv4_prefix(prefix, prefixlen)
        return self._send_message(ZEBRA_ROUTE_DELETE, data)

    def close(self):
        """ Close connection to Zebra """
        if self.sock:
            self.sock.close()
            self.sock = None

class DVMRPRouteManager:
    """
    Manages DVMRP routes and injects them into Zebra
    Replace the route learning mechanism with actual DVMRP neighbor communication
    """
    
    def __init__(self, zapi_client: ZAPIClient):
        self.zapi = zapi_client
        self.logger = logging.getLogger('dvmrp-manager')
        self.active_routes: Dict[str, dict] = {}  # Track active routes for cleanup

    def _learn_routes_from_dvmrp(self) -> list:
        """
        Learn routes from the DVMRP domain.
        
        This is where you integrate with your actual DVMRP source.
        Implementation options:

        1. Parse mrouted output: mrouted -c "show routes"
        2. Listen on DVMRP probe messages (multicast 224.0.0.4)
        3. Read from a socket where a DVMRP daemon sends updates
        4. Parse syslog or log files from your DVMRP implementation

        Returns list of (prefix, prefixlen, nexthop, metric) tuples
        """
        routes = []

        # === METHOD 1: Parse from file (example) ===
        # You can replace this with actual DVMRP route discovery
        route_file = '/var/run/dvmrp_routes.txt'
        if os.path.exists(route_file):
            try:
                with open(route_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            prefix, prefixlen, nexthop = parts[0], int(parts[1]), parts[2]
                            metric = int(parts[3]) if len(parts) > 3 else 20
                            routes.append((prefix, prefixlen, nexthop, metric))
            except Exception as e:
                self.logger.error(f"Error reading route file: {e}")

        # === METHOD 2: Parse mrouted output (commented out) ===
        # import subprocess
        # import re
        # try:
        #     result = subprocess.run(['mrouted', '-c', 'show routes'], 
        #                            capture_output=True, text=True, timeout=5)
        #     # Example parsing (adjust regex based on your mrouted output format)
        #     pattern = r'(\d+\.\d+\.\d+\.\d+)/(\d+)\s+via\s+(\d+\.\d+\.\d+\.\d+)'
        #     for line in result.stdout.split('\n'):
        #         match = re.search(pattern, line)
        #         if match:
        #             prefix = match.group(1)
        #             prefixlen = int(match.group(2))
        #             nexthop = match.group(3)
        #             routes.append((prefix, prefixlen, nexthop, 20))
        # except Exception as e:
        #     self.logger.warning(f"Failed to parse mrouted output: {e}")

        # === METHOD 3: Example static routes for testing ===
        # Remove this in production and use dynamic discovery
        if not routes:  # Only add static if no dynamic routes found
            self.logger.info("No dynamic routes found, adding test static routes")
            routes.append(('192.168.122.0', 24, '192.168.122.1', 20))
            routes.append(('10.0.0.0', 8, '192.168.122.1', 30))

        return routes

    def sync_routes(self) -> None:
        """ Sync DVMRP routes with Zebra """
        current_routes = set()

        routes = self._learn_routes_from_dvmrp()
        
        # Add or update routes
        for prefix, prefixlen, nexthop, metric in routes:
            route_key = f"{prefix}/{prefixlen}"
            current_routes.add(route_key)

            # Check if this is a new or changed route
            existing = self.active_routes.get(route_key)
            if not existing or existing['nexthop'] != nexthop or existing['metric'] != metric:
                self.logger.info(f"Adding/updating route: {route_key} via {nexthop} metric {metric}")
                if self.zapi.add_route(prefix, prefixlen, nexthop, metric):
                    self.active_routes[route_key] = {'nexthop': nexthop, 'metric': metric}
                else:
                    self.logger.error(f"Failed to add route {route_key}")

        # Remove routes that no longer exist in DVMRP domain
        for route_key in list(self.active_routes.keys()):
            if route_key not in current_routes:
                self.logger.info(f"Removing stale route: {route_key}")
                prefix, prefixlen = route_key.split('/')
                if self.zapi.delete_route(prefix, int(prefixlen)):
                    del self.active_routes[route_key]

    def run(self, interval: int = 30) -> None:
        """ Main loop: sync routes periodically """
        self.logger.info("Starting DVMRP route manager")
        while True:
            try:
                self.sync_routes()
            except Exception as e:
                self.logger.error(f"Error during route sync: {e}")
            time.sleep(interval)


def check_frr_socket():
    """Check if FRR socket exists and find the correct path"""
    possible_paths = [
        '/var/run/frr/zserv.api',
        '/var/run/frr/zserv.api.orig',
        '/var/run/frr/zebra.api',
        '/run/frr/zserv.api',
        '/var/run/zserv.api'
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('main')
    
    # First check if FRR is running
    import subprocess
    try:
        result = subprocess.run(['systemctl', 'is-active', 'frr'], 
                               capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("FRR service is not running. Start it with: systemctl start frr")
            sys.exit(1)
    except:
        logger.warning("Could not check FRR service status")
    
    # Find the correct ZAPI socket
    socket_path = check_frr_socket()
    if not socket_path:
        logger.error("Could not find FRR ZAPI socket. Make sure FRR is running with zebra enabled.")
        logger.info("Check: systemctl status frr")
        logger.info("Check: ls -la /var/run/frr/")
        sys.exit(1)
    
    logger.info(f"Using ZAPI socket: {socket_path}")
    
    # Wait for Zebra to be ready
    time.sleep(2)
    
    client = ZAPIClient(socket_path=socket_path)
    if not client.connect():
        logger.error("Failed to connect to Zebra. Is FRR running with zebra enabled?")
        logger.info("Check configuration: grep 'zebra=' /etc/frr/daemons")
        sys.exit(1)
    
    manager = DVMRPRouteManager(client)
    
    try:
        manager.run()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        client.close()

if __name__ == '__main__':
    main()



















