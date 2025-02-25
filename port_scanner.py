import socket
import ipaddress
import common_ports


def get_open_ports(target, port_range, verbose=False):
    [start_port, end_port] = port_range
    if verbose:
        string = ""
        if target[0].isnumeric():
            try:
                ip = ipaddress.ip_address(target)
                url = socket.gethostbyaddr(str(ip))[0]
                string += f"Open ports for {url} ({ip})\n"
                string += "PORT     SERVICE\n"
                for port in range(start_port, end_port + 1):
                    if scan_port(target, port):
                        string += "%-9s%s\n" % (
                            port, common_ports.ports_and_services[port])
            except Exception:
                string += "Error: Invalid IP address"

        else:
            try:
                ip = socket.gethostbyname(target)
                url = target
                string += f"Open ports for {url} ({ip})\n"
                string += "PORT     SERVICE\n"
                for port in range(start_port, end_port + 1):
                    if scan_port(target, port):
                        string += "%-9s%s\n" % (
                            port, common_ports.ports_and_services[port])
            except Exception:
                string += "Error: Invalid hostname"

        return string
    else:
        open_ports = []
        for port in range(start_port, end_port + 1):
            if scan_port(target, port):
                open_ports.append(port)

        return (open_ports)


def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


# print(get_open_ports("sccaasdfnme.nmap", [443, 445], True))
# print(get_open_ports("104.26.10.78", [443, 445], True))