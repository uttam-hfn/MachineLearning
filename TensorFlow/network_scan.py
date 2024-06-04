import socket
import ipaddress
import requests
from requests.exceptions import RequestException
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def get_local_ip():
    """Get the local IP address of the current machine."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_network_prefix(ip):
    """Get the network prefix (e.g., 192.168.1.) from an IP address."""
    ip_obj = ipaddress.ip_address(ip)
    network_prefix = ip.split('.')[:-1]
    return '.'.join(network_prefix) + '.'

def scan_network(prefix):
    """Scan the network for active devices using ARP requests."""
    arp = ARP(pdst=prefix + '1/24')
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def check_camera(ip):
    """Check if the given IP address is likely a camera by looking for common camera ports and web interfaces."""
    common_ports = [80, 8080, 554, 8000]
    for port in common_ports:
        url = f'http://{ip}:{port}'
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                if 'camera' in response.text.lower() or 'video' in response.text.lower():
                    return True
        except RequestException:
            pass
    return False

def main():
    local_ip = get_local_ip()
    network_prefix = get_network_prefix(local_ip)
    devices = scan_network(network_prefix)

    print(f"Found {len(devices)} devices in the network.")

    for device in devices:
        ip = device['ip']
        print(ip)
        if check_camera(ip):
            print(f"Camera found at IP: {ip}")

if __name__ == "__main__":
    main()

#%%
