# Erik Safford
# traceroute() Implementation in Python
# CS 455
# Fall 2019

import socket
import sys
import random
import struct
import time

# Creates a receiver socket using the SOCK_RAW and ICMP protocols
def create_receiver(port):
    s = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=socket.IPPROTO_ICMP
    )

    # Build a timeval struct (seconds, microseconds)
    timeout = struct.pack("ll", 5, 0)
    # Set the recieve timeout (SO_RCVTIMEO) so receiver does not hang on long responses
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

    try:
        s.bind(('', port))
    except socket.error:
        print('Unable to bind receiver socket')

    return s

# Creates a sender socket using the UDP datagram protocol
def create_sender(ttl):
    s = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP
    )

    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    return s

# Main function
def trace():
    # Exit if a route to trace isn't specified
    if len(sys.argv) != 2 :
        print("Error: Make sure to specify a route (IP) to trace")
        print("Ex: /usr/bin/python traceroute.py google.com")
        exit()

    # Save route, set router hop limit and initial ttl
    route = sys.argv[1]
    hops = 30
    ttl = 1

    # Pick a random port to bind to in the range of 33434-33534
    port = random.choice(range(33434, 33535))

    # Attempt to get the host (IP) of the specified route
    print("Attempting to get host of '" + route + "'")
    try:
        dest_ip = socket.gethostbyname(route)
    except socket.error:
        print("Error: Unable to get host for specified route")
        exit()
    print("Host '" + dest_ip + "' discovered successfully")

    # Print route/host/hops information
    print("traceroute to {} ({}), {} hops max".format(route, dest_ip, hops))

    # Start traceroute() routine
    info_string = ''
    packets_sent = 0  # Want to send a total of 3 packets for each TTL
    while True:
        # Reset the info_string if three packets were sent to a single TTL
        if packets_sent == 3:
            info_string = ''  # Reset previous TTL info string
            packets_sent = 0  # Reset number of packets sent w/ single TTL

        # Create senders and receivers to send UDP packet/receive ICMP Time Exceeded error response
        receiver = create_receiver(port)
        sender = create_sender(ttl)

        # Send a blank UDP packet to the route on chosen port
        sender.sendto(b'', (route, port))
        # Save the time the packet was sent at to determine RTT later
        start_time = time.time()

        # Attempt to recieve a ICMP response from the host
        addr = None
        try:
            # 'data' is data sent to receiver (ICMP contents), 'addr[0]' is the address of the socket sending the data
            data, addr = receiver.recvfrom(1024)
            # Capture end time that ICMP packet was received
            end_time = time.time()
        # If ICMP response could not be received, error
        except socket.error:
            print("socket receive error")
            pass
        
        # Close the receiver and sender sockets
        receiver.close()
        sender.close()

        # Increment total packets sent with same ttl
        packets_sent += 1

        # If a socket responded w/ an ICMP response to the UDP packet sent by sender   
        if addr:
            # Calculate the RTT by substracting the start_time from the end_time
            rtt = round((end_time - start_time) * 1000, 2)

            # Format route and transmission delays of packets into single string to be printed once 3 packets are sent w/ same TTL
            if packets_sent == 1:
                info_string = ('{}  {} ms').format(ttl, rtt)
            elif packets_sent == 2:
                info_string += ('  {} ms').format(rtt)
            elif packets_sent == 3:
                info_string += ('  {} ms  ({})').format(rtt, addr[0])
                print(info_string)
                # break if destination route has been reached
                if addr[0] == dest_ip:
                    break  
        else:
            print('{} *'.format(ttl))

        # If three packets have been sent (and three RTT's calculated)
        if packets_sent == 3:
            ttl += 1

        # Break if router hop limit exceeded
        if ttl > hops:
            break

trace()