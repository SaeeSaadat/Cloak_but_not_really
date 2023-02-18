import queue
import socket
import logging
import multiprocessing as mp
from multiprocessing import Queue
import sys
import argparse
import time
import ssl
from select import select
from typing import Tuple, Optional

UDP_RCV_BUFFER_SIZE = 2048
TCP_RCV_BUFFER_SIZE = 2048


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-ut', '--udp-tunnel', action='append', required=True,
                        help="Make a tunnel from the client to the server. The format is\
                              'listening ip:listening port:remote ip:remote port'.")
    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    return parser.parse_args()


def send_udp_packet(sock: socket.socket, host, port, packet: bytes):
    logging.info(f"Sent packet to {host}:{port} -> {packet}\n")
    sock.sendto(packet, (host, port))


def handle_tcp_connection(tcp_socket, server_addr, remote_addr, request_queue: Queue, response_queue: Queue, addr,
                          verbosity):
    """
    read from tcp socket for the UDP segment received through the tunnel,
    then forward received segment to incom_udp_addr
    """
    configure_logging(verbosity)

    try:
        # wrap our TCP socket in a ssl wrapper to use SSL for handshakes and encryption.
        stcp_socket = ssl.wrap_socket(tcp_socket, certfile="cert.pem", keyfile="key.pem")

        stcp_socket.connect(server_addr)

        # Send the server information as the first message
        stcp_socket.sendall(f"REMOTE,{remote_addr[0]},{remote_addr[1]}".encode())
        response = stcp_socket.recv(256).decode()
        if response != "OK":
            logging.error(response)
            return None

        # Using select in a loop, we'll check if there's anything to read from remote server and
        # put in the response_queue or if we need to send anything from request_queue to the remote server,
        while True:
            input_ready, output_ready, _ = select([stcp_socket], [stcp_socket], [])
            for s in input_ready:
                packet = s.recv(TCP_RCV_BUFFER_SIZE)
                if not packet:
                    logging.error("TCP Connection to XServer closed")
                    s.close()
                    return
                response_queue.put((packet, addr))
                logging.info(f"{addr}: Packet received from XServer and was put in the response queue.")
            for s in output_ready:
                try:
                    packet = request_queue.get_nowait()
                    try:
                        s.sendall(packet)
                    except BrokenPipeError as e:
                        logging.error(e)
                        s.close()
                        return
                    logging.info(f"{addr}: Packet sent to XServer.")
                except queue.Empty:
                    pass

    except (KeyboardInterrupt, ConnectionError) as e:
        logging.warning(f"{addr}: Closing the connection to XServer because of {e}")
        tcp_socket.close()
        return


def establish_new_tcp_connection_to_xserver(host, port, remote_ip, remote_port, request_queue, response_queue, addr,
                                            verbosity) -> Optional[Tuple[socket.socket, mp.Process]]:
    """
    Initiates a new tcp connection to XServer and returns the created socket
    Upon the initiation sends the remote (server) UDP address in the first message to XServer
    Afterwards, starts the TCP process which is responsible for listening and sending packets to the TCP connection to
    our XServer using queues to communicate with the main process.
    :return: (STCP Socket, TCP Process)
    """

    # Create the TCP socket and connect to XServer
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_process = mp.Process(target=handle_tcp_connection,
                             args=(sock, (host, port), (remote_ip, remote_port),
                                   request_queue, response_queue, addr, verbosity))
    tcp_process.start()

    return sock, tcp_process


def handle_udp_conn(
        udp_listening_port: int,
        udp_socket: socket.socket,
        tcp_server_addr: Tuple[str, int],
        rmt_udp_addr: Tuple[str, int],
        verbosity: str = 'debug'
):
    """
        Receive a UDP packet form incom_udp_addr.
        It also keeps the associated thread for handling tcp connections in tcp_conn_list,
        if incom_udp_addr not in udp_conn_list, Recognize a new UDP connection from incom_udp_addr.
        So establish a TCP connection to the remote server for it
        and if incom_udp_addr in tcp_conn_list will continue sending in established socket,
    """

    # Initiating the dictionary which maps each clientApp (using their port number) to each TCP connection
    tcp_conn_list: dict[Tuple[str, int], socket.socket] = {}
    queues_list: dict[Tuple[str, int], Tuple[Queue, Queue]] = {}
    configure_logging(verbosity)

    # Create the queues (used for communication between TCP process and UDP process
    tcp_process = None

    try:
        while True:
            input_ready, output_ready, _ = select([udp_socket], [udp_socket], [])
            for s in input_ready:
                # Receive message from ClientApp
                packet, address = s.recvfrom(UDP_RCV_BUFFER_SIZE)
                logging.info(f"Packet from Client @ {address} -> {packet}")

                # Check if a TCP connection already exists for this client, and if not, create one for it.
                if address not in tcp_conn_list:
                    response_queue = Queue()
                    request_queue = Queue()
                    queues_list[address] = (request_queue, response_queue)
                    tcp_conn_list[address], tcp_process = \
                        establish_new_tcp_connection_to_xserver(*tcp_server_addr, *rmt_udp_addr, request_queue,
                                                                response_queue, address, verbosity)

                tcp_sock = tcp_conn_list[address]
                request_queue, response_queue = queues_list[address]
                if tcp_sock is None:
                    return

                # In case connection is closed
                if not packet:
                    logging.warning(f"{address}: Connection closed!")
                    tcp_process.kill()
                    if tcp_sock:
                        tcp_sock.close()
                        del tcp_conn_list[address]
                        del queues_list[address]
                    return

                # put the request into the request_queue so TCP process can handle it
                request_queue.put(packet)

            for s in output_ready:
                for response_queue in list(map(lambda x: x[1], queues_list.values())):
                    try:
                        packet, address = response_queue.get_nowait()
                        logging.info(f"{address}: got response packet from queue, sending it to client now -> {packet}")
                        send_udp_packet(s, *address, packet)
                    except queue.Empty:
                        pass

    except KeyboardInterrupt:
        logging.info(f"Closing {len(tcp_conn_list.values())} TCP Connections on the port {udp_listening_port}")
        # Close all tcp connections
        for sock in tcp_conn_list.values():
            sock.close()


def configure_logging(verbosity):
    if verbosity == 'error':
        log_level = logging.ERROR
    elif verbosity == 'info':
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(asctime)s %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler("logs/XClient.log"),
            logging.StreamHandler()
        ]
    )


def start_client(
        tcp_server_ip,
        tcp_server_port,
        udp_tunnels,
        verbosity
):
    configure_logging(verbosity)

    for tunnel in udp_tunnels:
        print(tunnel)
        udp_listening_ip, udp_listening_port, rmt_udp_ip, rmt_udp_port = tunnel

        try:
            udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((udp_listening_ip, udp_listening_port))
        except socket.error as e:
            logging.error("(Error) Error opening the UDP socket: {}".format(e))
            logging.error(
                "(Error) Cannot open the UDP socket {}:{} or bind to it".format(udp_listening_ip, udp_listening_port))
            sys.exit(1)
        else:
            logging.info("Bind to the UDP socket {}:{}".format(udp_listening_ip, udp_listening_port))

        mp.Process(target=handle_udp_conn,
                   args=(udp_listening_port, udp_socket, (tcp_server_ip, tcp_server_port), (rmt_udp_ip, rmt_udp_port)))\
            .start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Goodbye!")


def main():
    args = parse_input_argument()

    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])

    udp_tunnels = []
    for tun_addr in args.udp_tunnel:
        tun_addr_split = tun_addr.split(':')
        udp_listening_ip = tun_addr_split[0]
        udp_listening_port = int(tun_addr_split[1])
        rmt_udp_ip = tun_addr_split[2]
        rmt_udp_port = int(tun_addr_split[3])
        udp_tunnels.append((udp_listening_ip, udp_listening_port, rmt_udp_ip, rmt_udp_port))

    start_client(tcp_server_ip, tcp_server_port, udp_tunnels, args.verbosity)


if __name__ == "__main__":
    main()
