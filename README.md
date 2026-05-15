# pysslscan.py
A professional-grade SSL/TLS security scanner designed for     penetration testers, system administrators, and security researchers.     It analyzes SSL/TLS configurations, identifies weak protocols, detects     known vulnerabilities, and provides actionable security recommendations.
# PySSLScan - Simple SSL/TLS Scanner

Lightweight SSL/TLS security scanner for Termux & Kali Linux.
██████╗ ██╗   ██╗███████╗███████╗██╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
   ██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██║      ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ██████╔╝ ╚████╔╝ ███████╗███████╗██║█████╗███████╗██║     ███████║██╔██╗ ██║
   ██╔═══╝   ╚██╔╝  ╚════██║╚════██║██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║
   ██║        ██║   ███████║███████║██║      ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═╝        ╚═╝   ╚══════╝╚══════╝╚═╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
## Quick Start

```bash
# Download
wget https://raw.githubusercontent.com/MrMercerCyberSec/pysslscan.py/main/pysslscan.py

# Run
python pysslscan.py example.com
python pysslscan.py target.com              # Basic scan
python pysslscan.py target.com -p 8443      # Custom port
python pysslscan.py target.com -o report    # Save JSON
python pysslscan.py target.com --threads 10 # Fast scan
