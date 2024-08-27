import argparse
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import nmap
import ssl
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init()

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = socket.getservbyport(port)
            return port, True, service
        else:
            return port, False, None
    except:
        return port, False, None
    finally:
        sock.close()

def port_scan(target, ports):
    print(f"{Fore.BLUE}[*] Starting port scan for {target}{Style.RESET_ALL}")
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)
        for port, is_open, service in results:
            if is_open:
                print(f"{Fore.GREEN}[+] Port {port} is open - Service: {service}{Style.RESET_ALL}")
                open_ports.append(port)
            else:
                print(f"{Fore.RED}[-] Port {port} is closed{Style.RESET_ALL}")
    return open_ports

def os_detection(target):
    print(f"{Fore.BLUE}[*] Attempting OS detection for {target}{Style.RESET_ALL}")
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-O")
    if 'osmatch' in nm[target]:
        os_matches = nm[target]['osmatch']
        if os_matches:
            print(f"{Fore.GREEN}[+] OS Detection Results:{Style.RESET_ALL}")
            for os in os_matches:
                print(f"    Name: {os['name']}, Accuracy: {os['accuracy']}%")
        else:
            print(f"{Fore.YELLOW}[!] Could not determine OS{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] OS detection failed{Style.RESET_ALL}")

def check_ssl(target, port=443):
    print(f"{Fore.BLUE}[*] Checking SSL/TLS configuration for {target}:{port}{Style.RESET_ALL}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                cert = secure_sock.getpeercert()
                print(f"{Fore.GREEN}[+] SSL/TLS connection established{Style.RESET_ALL}")
                print(f"    Version: {secure_sock.version()}")
                print(f"    Cipher: {secure_sock.cipher()[0]}")
                print(f"    Expires: {cert['notAfter']}")
    except ssl.SSLError as e:
        print(f"{Fore.RED}[-] SSL/TLS error: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error checking SSL/TLS: {e}{Style.RESET_ALL}")

def check_http_security_headers(target):
    print(f"{Fore.BLUE}[*] Checking HTTP security headers for {target}{Style.RESET_ALL}")
    try:
        response = requests.get(f"https://{target}", timeout=5)
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Frame-Options': 'X-Frame-Options',
            'X-XSS-Protection': 'XSS Protection',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'Referrer-Policy': 'Referrer Policy',
            'Content-Security-Policy': 'CSP'
        }
        
        print(f"{Fore.GREEN}[+] Security Headers:{Style.RESET_ALL}")
        for header, description in security_headers.items():
            if header in headers:
                print(f"    {description}: {headers[header]}")
            else:
                print(f"{Fore.YELLOW}    {description}: Not set{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Error checking HTTP headers: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Network Security Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", type=int, nargs="+", default=range(1, 1001),
                        help="Ports to scan (default: 1-1000)")
    args = parser.parse_args()

    print(f"{Fore.CYAN}Starting Network Security Scanner for {args.target}{Style.RESET_ALL}")
    
    open_ports = port_scan(args.target, args.ports)
    
    if open_ports:
        os_detection(args.target)
        
        if 443 in open_ports:
            check_ssl(args.target)
        
        if 80 in open_ports or 443 in open_ports:
            check_http_security_headers(args.target)
    
    print(f"{Fore.CYAN}Scan completed for {args.target}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
