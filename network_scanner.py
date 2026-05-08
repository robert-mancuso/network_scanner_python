import errno
import socket


# function accepts a hostname and returns a tuple pair of (hostname, ip_address)
def resolve_target_host(target):
    try:
        # if target is a hostname:
        ip_address = socket.gethostbyname(target)
        # get actual host name, only need the first value:
        host_name = socket.gethostbyaddr(ip_address)[0]
        return host_name, ip_address
    except socket.gaierror as e:
        print(f"Address-related error: {e}")
    except socket.error as e:
        print(f"Generic socket error: {e}")
    return None, None


# function takes a host DNS number and a port number, and a length of time to wait.
# returns either "open" or reason why it might be closed
def check_port(host, port, timeout=2.0):
    # client-side connection:
    # SOCK_STREAM is TCP, won't work for UDP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        # connect_ex returns integer for error indicator
        # establishes connection to remote socket:
        connection_result = s.connect_ex((host, port))

        # if connection failed, try to give reason why:
        if connection_result == 0:
            # handshake completed
            return "Open"
        elif connection_result == errno.ECONNREFUSED:
            return "Closed (Connection Refused)"
        elif connection_result == errno.ETIMEDOUT:
            return "Filtered (Timeout/No Response)"
        else:
            return f"Error (Code: {connection_result})"


# common ports, manually defined, most likely to be needed:
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
}

# main with hard-coded test values:
if __name__ == "__main__":
    # Prompt user for input:
    user_input = input("Enter a hostname to scan for: ").strip()
    print(f"\nResolving target information...")
    # resolve hostname to ip address via helper function:
    host_name, target_ip = resolve_target_host(user_input)

    if target_ip == None:
        print(
            f"Error: Could not resolve '{user_input}'. Check connection or try again."
        )
    else:
        print("=" * 40)
        print(f"Target Host: {host_name}")
        print(f"Target IP: {target_ip}")

    # loop through the dictionary of common ports:
    for port, service in common_ports.items():
        status = check_port(target_ip, port)
        print(f"Port {port} ({service}): {status}")
#    print(f"Port {target_port} on {target_host} is: {status}")
