```markdown
# HydraStorm
Network Load Testing and Security Assessment Tool

## Legal Disclaimer
This software is provided for authorized security testing and research purposes only. Users are solely responsible for ensuring they have proper authorization before conducting any tests. Unauthorized use violates computer crime laws in most jurisdictions.

## Installation

### Kali Linux
```bash
sudo apt update && sudo apt install -y python3 python3-pip scapy
git clone https://github.com/caleb-elie/HydraStorm.git
cd HydraStorm
pip install -r requirements.txt
```

### Windows
1. Install Python 3.10+ from python.org
2. Install Npcap (https://npcap.com)
3. Run:
```powershell
git clone https://github.com/caleb-elie/HydraStorm.git
cd HydraStorm
pip install -r requirements.txt
```

## Configuration
Modify `config.ini`:
```ini
[DEFAULT]
target = target.example.com  # Required: Test target
duration = 300               # Test duration (seconds)
threads = 100                # Concurrent connections
log_level = INFO             # DEBUG|INFO|WARNING|ERROR
```

## Usage Examples

### Basic Operation
```bash
python ddos.py
```

### Advanced Testing
```bash
# Targeted service test
python ddos.py --target 192.168.1.100 --port 443 --duration 600

# Debug mode with packet capture
DEBUG=1 PCAP=1 python ddos.py
```

### Malware Analysis
```bash
# Sandboxed execution with traffic monitoring
docker run --network host -it hydrastorm python ddos.py --duration 30
```

## Features
- Protocol: HTTP/HTTPS layer 7 traffic generation
- Evasion: IP/TLS fingerprint randomization
- Monitoring: Built-in packet capture (PCAP) support
- Analysis: Detailed traffic logging

## Output Files
- `attack_log.txt`: Timestamped request/response data
- `traffic.pcap` (when enabled): Network capture

## Security Professionals
For malware analysis:
1. Execute in controlled environments
2. Monitor with Wireshark/tcpdump
3. Analyze generated PCAP files
4. Review memory artifacts

## License
MIT License - See LICENSE for complete terms
```
