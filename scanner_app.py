import socket
import time
import requests
import logging
import os
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
scanner_logger = logging.getLogger('PortScanner')

class HostPortScanner:
    def __init__(self):
        self.receiver_url = os.getenv('RECEIVER_URL', 'http://localhost:5000/receive')
        self.scan_interval = int(os.getenv('SCAN_INTERVAL', '300'))  # Default 5 minutes
        self.host_identifier = os.getenv('HOST_IDENTIFIER', socket.gethostname())
        self.tcp_ports_to_scan = self._parse_ports(os.getenv('TCP_PORTS_TO_SCAN', '1-1024'))
        self.udp_ports_to_scan = self._parse_ports(os.getenv('UDP_PORTS_TO_SCAN', ''))
        self.scan_timeout = float(os.getenv('SCAN_TIMEOUT', '0.5'))  # seconds

    def _parse_ports(self, port_str: str) -> List[int]:
        """Convert port range string (like '1-1024') to list of ports"""
        if not port_str:
            return []
        
        ports = []
        for part in port_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

    def _check_tcp_port(self, port: int) -> bool:
        """Check if a TCP port is open"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.scan_timeout)
            try:
                sock.connect(('localhost', port))
                return True
            except (socket.timeout, ConnectionRefusedError):
                return False

    def _check_udp_port(self, port: int) -> bool:
        """Check if a UDP port appears open (UDP scanning is unreliable by nature)"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.scan_timeout)
            try:
                sock.sendto(b'', ('localhost', port))
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                # Might be open but not responding
                return False
            except ConnectionRefusedError:
                return False

    def scan_ports(self) -> Dict[str, List[int]]:
        """Scan all configured ports and return open ones"""
        open_ports = {'tcp': [], 'udp': []}
        
        scanner_logger.info(f"Starting TCP port scan for {len(self.tcp_ports_to_scan)} ports")
        for port in self.tcp_ports_to_scan:
            if self._check_tcp_port(port):
                open_ports['tcp'].append(port)
                scanner_logger.debug(f"TCP port {port} is open")
        
        scanner_logger.info(f"Starting UDP port scan for {len(self.udp_ports_to_scan)} ports")
        for port in self.udp_ports_to_scan:
            if self._check_udp_port(port):
                open_ports['udp'].append(port)
                scanner_logger.debug(f"UDP port {port} is open")
        
        scanner_logger.info(f"Scan complete. Found {len(open_ports['tcp'])} TCP and {len(open_ports['udp'])} UDP ports open")
        return open_ports

    def send_results(self, open_ports: Dict[str, List[int]]) -> bool:
        """Send scan results to receiver"""
        payload = {
            'host_identifier': self.host_identifier,
            'timestamp': int(time.time()),
            'open_ports': open_ports
        }
        
        try:
            response = requests.post(self.receiver_url, json=payload)
            if response.status_code == 200:
                scanner_logger.info("Results successfully sent to receiver")
                return True
            else:
                scanner_logger.error(f"Receiver returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            scanner_logger.error(f"Failed to send results: {str(e)}")
            return False

    def run_continuously(self):
        """Run scans continuously at the configured interval"""
        scanner_logger.info("Starting continuous port scanning")
        while True:
            try:
                open_ports = self.scan_ports()
                self.send_results(open_ports)
            except Exception as e:
                scanner_logger.error(f"Error during scan cycle: {str(e)}")
            
            time.sleep(self.scan_interval)

if __name__ == '__main__':
    scanner = HostPortScanner()
    scanner.run_continuously()
