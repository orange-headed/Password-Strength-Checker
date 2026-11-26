import socket
import nmap
from datetime import datetime

def port_scan(target, start_port, end_port):
    print(f"Scanning target: {target} for open_ports from {start_port} to {end_port}...")
    open_ports = []
    for port in range(start_port,end_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.1)
        result = sock.connect_ex((target,port))
        if result == 0:
            open_ports.append(port)
        else:
            sock.close()
    return open_ports


def vulnerability_scan(target):
    print(f"Scanning the target {target} for Vulnerability.....")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target,arguments="-O -sV --script=vuln")
        return nm[target]
    except Exception as e:
        print(f"Error during vulnerability scan: {e}")
        return None


def banner_grab(target,port):
    print(f"Grabbing banner for {target}:{port}")

    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((target,port))
        sock.settimeout(2)
        banner = sock.recv(1024).decode('utf-8',errors="ignore")
        sock.close()
        return banner.strip()
    except:
        return None


def network_scan(target,start_port,end_port):
    print(f"Starting network scan for target : {target}..")
    start_time = datetime.now()

    open_ports = port_scan(target, start_port, end_port)
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found!")

    for port in open_ports:
        banner = banner_grab(target,port)
        if banner:
            print(f"Banner for {target}:{port} - {banner}")
        else:
            print(f"No banner found for {target}:{port}")

    vuln_info = vulnerability_scan(target)
    if vuln_info:
        if 'hostnames' in vuln_info:
            print(f"Hostnames: {vuln_info['hostname']}")

        if 'osmatch' in vuln_info:
            print(f"Operating System : {vuln_info['osmatch']}")

        if 'vulns' in vuln_info:
            print(f"Vulnerabilities : {vuln_info['vulns']}")
    else:
        print("No vulnerabilities detect or unable to detect")

    end_time = datetime.now()
    print(f"Scan completed in:{end_time - start_time}")




if __name__ == "__main__":
    target_ip = input("Enter the tagert IP or Hostname: ")
    start_port = int(input("Enter the starting port for scanning: "))
    end_port = int(input("Enter the ending port for scanning: "))
    network_scan(target_ip, start_port, end_port)