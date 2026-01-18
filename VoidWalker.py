import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import time
#MDV 17/01/26
# Costanti per lo stile ANSI (Colori)
G = '\033[92m'  # Verde (Safe/Info)
Y = '\033[93m'  # Giallo (Warning)
R = '\033[91m'  # Rosso (Danger/Botnet)
C = '\033[96m'  # Cyan (System)
W = '\033[0m'   # Reset

class IoTSentry:
    def __init__(self):
        # Mappatura porte Botnet/Backdoor
        self.BOTNET_PORTS = {
            23: "Telnet (Mirai/Gafgyt Target)",
            2323: "Telnet Alt (Mirai Target)",
            5555: "ADB (Kimwolf/Android Botnet)",
            37215: "Huawei UPnP Exploit",
            52869: "Realtek SDK Vulnerability",
            4321: "Potential Backdoor"
        }
        # Mappatura porte configurazione errata
        self.DANGER_PORTS = {
            21: "FTP (Insecure)",
            445: "SMB (Worm/Lateral Movement)",
            1900: "UPnP SSDP (DDoS Vector)",
            5431: "UPnP Config Interface",
            8080: "HTTP Proxy/Admin UI"
        }

    def get_local_ip(self):
        """Rileva l'IP locale della macchina"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def print_banner(self):
        local_ip = self.get_local_ip()
        print(f"""
{C}#################################################
#           VoidWalker - NETWORK AUDITOR        #
#      "Protecting the local mesh from botnets" #
#################################################{W}
[>] Local IP Detected: {G}{local_ip}{W}
[>] Network Status: Monitoring for IoT Threats...
""")

    def grab_banner(self, sock):
        """Tenta di leggere la firma del servizio (Banner Grabbing)"""
        try:
            # Alcuni servizi inviano un banner appena ti connetti (FTP, Telnet, SSH)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            if banner:
                return f"Banner: {banner[:50]}..." 
            return "No banner detected (Silent service)"
        except:
            return "Could not grab banner (Timeout/No response)"

    def scan_port(self, ip, port):
        """Esegue il check della porta e tenta il grabbing del banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5) # Leggermente più alto per permettere il banner grab
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    # Se la porta è aperta, proviamo a prendere il banner
                    banner_info = self.grab_banner(s)
                    return port, banner_info
        except:
            pass
        return None, None

    def audit_host(self, ip):
        """Scansiona un singolo host per tutte le porte definite"""
        findings = []
        all_ports = {**self.BOTNET_PORTS, **self.DANGER_PORTS}
        
        for port in all_ports:
            res_port, banner = self.scan_port(ip, port)
            if res_port:
                category = f"{R}[BOTNET RISK]" if res_port in self.BOTNET_PORTS else f"{Y}[CONFIG RISK]"
                desc = all_ports[res_port]
                findings.append(f"    {category} Port {res_port}: {desc}\n        |_ {C}{banner}{W}")
        
        if findings:
            with threading.Lock():
                print(f"{C}[+]{W} Host found: {G}{ip}{W}")
                for f in findings:
                    print(f)

    def run(self, network_input):
        try:
            network = ipaddress.ip_network(network_input, strict=False)
            hosts = list(network.hosts())
            print(f"[*] Starting audit on {len(hosts)} potential hosts...")
            print("-" * 60)
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(self.audit_host, hosts)
                
        except ValueError:
            print(f"{R}[!] Error: Invalid Network Range.{W}")
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Audit interrupted by user.{W}")

if __name__ == "__main__":
    scanner = IoTSentry()
    scanner.print_banner()
    
    target = input(f"Enter target network (Press Enter for {scanner.get_local_ip().rsplit('.', 1)[0]}.0/24): ")
    if not target:
        target = f"{scanner.get_local_ip().rsplit('.', 1)[0]}.0/24"
    
    start_time = time.time()
    scanner.run(target)
    end_time = time.time()
    
    print("-" * 60)
    print(f"[*] Audit finished in {round(end_time - start_time, 2)} seconds.")

