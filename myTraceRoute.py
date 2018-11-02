from socket import * 
import sys
import io
import struct
import time

MAX_HOPS = 30
TIMEOUT = 4
TRIES = 3


# Wraps stdout into a console. Flushes after each call to write()
class console(io.FileIO):
    def __init__(self, infile):
        self.infile = infile
    def write(self, x):
        self.infile.write(x)
        self.infile.flush()
sys.stdout = console(sys.stdout)


def traceroute(dest_name):
    # Get destination IP address from the destination name
    dest_addr = gethostbyname(dest_name)

    # By convention, hosts run ICMP at port 33434
    port_number = 33434

    for hop in range(1, MAX_HOPS + 1):
        current_addr = None
        current_name = None
        sys.stdout.write("%d  " %hop)

        for attempt in range(TRIES):
            # Create UDP sender socket with a TTL (i.e. current hop count)
            udp_socket = socket(AF_INET, SOCK_DGRAM, getprotobyname("udp"))
            udp_socket.setsockopt(SOL_IP, IP_TTL, hop)

            # Create ICMP receiver socket
            # Create timeout option struct for ICMP socket
            timeout_option = struct.pack('ll', TIMEOUT, 0)
            icmp_socket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            icmp_socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, timeout_option)
            icmp_socket.bind(("", port_number))

            # Get time of when message is sent to UDP socket 
            sent_time = time.time()

            # Attach destination name and port number to a simple test ping message, and send it to the UDP socket 
            ping_message = ""
            udp_socket.sendto(ping_message.encode(), (dest_name, port_number))

            try:
                # Get address received from the ICMP socket 
                _, current_addr = icmp_socket.recvfrom(1024)
                current_addr = current_addr[0]

                # Calculate RTT in milliseconds and print it to console
                elapsedTime = (time.time() - sent_time) * 1000
                sys.stdout.write("%s ms " %str(elapsedTime))

            except:
                # If exception occurs, such as timeout, then write "*"
                sys.stdout.write("* ")

            else:
                try:
                    # Try to get the name of the host that we made the hop to 
                    current_name = gethostbyaddr(current_addr)[0]
                except:
                    # If we cannot get hostname, just use IP address
                    current_name = current_addr
            
            finally:
                # Close sockets
                udp_socket.close()
                icmp_socket.close()

        # Print the hostname, IP address pair of the host that we made hop to, if it is a valid address
        if current_addr is not None:
            sys.stdout.write("     %s (%s)" %(current_name, current_addr))
        sys.stdout.write("\n")

        # If current hop address is the same as the requested destination address, return 
        if (current_addr == dest_addr):
            print("----- Done in %d hops -----" %hop)
            return

        # Exit if max number of hops is reached without finding destination 
        if hop == MAX_HOPS:
            print("---- Max number of hops reached ... terminating ----")
            exit(1)


if __name__=="__main__":
    hostname = sys.argv[1]
    print("---- traceroute to %s ----" %hostname)
    traceroute(hostname)