from scapy.all import ARP, Ether, srp
import argparse
import socket
import warnings
warnings.filterwarnings('ignore')

def get_arguments():
    """ Parse command-line arguments """
    parser = argparse.ArgumentParser(description="Automated Network Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()
    return args.target

def scan(ip):
    """ Scans the network to find live hosts """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    clients = []
    for element in answered_list:
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client)
    return clients

def scan_ports(ip):
    """ Scans for open ports on a given IP """
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def display_results(clients):
    """ Display the results in a readable format """
    print("\nLive Devices on the Network:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")
        open_ports = scan_ports(client['ip'])
        if open_ports:
            print(f"  Open Ports: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    target_ip = get_arguments()
    live_hosts = scan(target_ip)
    display_results(live_hosts)


