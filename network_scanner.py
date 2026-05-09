import errno
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from operator import itemgetter

# for thread-safe printing during scan_ports method
print_lock = threading.Lock()


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
def check_port(host, port, timeout=1.5):
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


# helper method to get name of service for ports
def get_service_name(port):
    # check the local list first
    if port in common_ports:
        return common_ports[port]
    try:
        # returns service and protocol name for a port number
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def scan_ports(host, port_range):
    port_list = list(port_range)
    total_ports = len(port_list)
    scanned_count = 0
    open_ports = []
    timeout = 1.0

    # lock counter to prevent race condition:
    counter_lock = threading.Lock()

    print(f"\nScanning {total_ports} with 100 threads...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        # futures will be printed the instant they finish, regardless of submission order
        futures = {}
        for port in port_list:
            # submits a method to be executed with the given arguments
            future = executor.submit(check_port, host, port, timeout)
            # this future is checking this port
            futures[future] = port

        # gather results as they complete
        for future in as_completed(futures):
            # recall what port was being checked once finished
            port = futures[future]

            # update the progress counter:
            with counter_lock:
                scanned_count += 1
                # print progress in a way that overwrites the same line:
                sys.stdout.write(f"\r Progress: {scanned_count}")
                # flush output from buffer
                sys.stdout.flush()

            status = future.result()

            # print open ports as found:
            if status == "Open":
                service = get_service_name(port)
                with print_lock:
                    # new line, print result, reprint progress:
                    sys.stdout.write(f"\r Port {port} ({service}): {status}\n")
                    sys.stdout.write(
                        f"Progress: {scanned_count}/{total_ports} ports scanned"
                    )
                    sys.stdout.flush()
            else:
                service = get_service_name(port)
                with print_lock:
                    sys.stdout.write(f"\r X Port {port} ({service}): {status}\n")
                    sys.stdout.write(
                        f"Progress: {scanned_count}/{total_ports} ports scanned"
                    )
                    sys.stdout.flush()
    # return list of open ports:
    return sorted(open_ports, key=itemgetter(0))


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

    print("\nScan range options:")
    print("  1) Common ports only (14 ports - fastest)")
    print("  2) Well-known ports (1-1024)")
    print("  3) Extended range (1-10,000)")
    print("  4) Full scan (1-65,535)")

    # ask user for range or default to 2
    range_choice = input("Select range [1-4] (default: 2): ").strip() or "2"

    if range_choice == "1":
        port_range = common_ports.keys()
    elif range_choice == "2":
        port_range = range(1, 1025)
    elif range_choice == "3":
        port_range = range(1, 10001)
    elif range_choice == "4":
        port_range = range(1, 65536)
    else:
        port_range = range(1, 1025)

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

    # run concurrent scan:
    open_ports = scan_ports(target_ip, port_range)

    """# loop through the dictionary of common ports:
    for port, service in common_ports.items():
        status = check_port(target_ip, port)
        print(f"Port {port} ({service}): {status}")
#    print(f"Port {target_port} on {target_host} is: {status}")"""
