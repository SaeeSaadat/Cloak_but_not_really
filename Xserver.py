import argparse
import queue
import socket
import multiprocessing as mp
import ssl
from multiprocessing import Queue
import logging
from select import select

UDP_RCV_BUFFER_SIZE = 2048
TCP_RCV_BUFFER_SIZE = 2048


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is the server program that the client will '
                                                 'make the TCP Connection to.')

    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    return parser.parse_args()


def init_socket(host, port) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    return s


def establish_udp_socket_to_remote_server() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_udp_packet(sock: socket.socket, host, port, packet: bytes):
    logging.info(f"Sent packet to {host}:{port} -> {packet}\n")
    sock.sendto(packet, (host, port))


def handle_remote_server(server_addr, request_queue: Queue, response_queue: Queue, addr, verbosity):
    configure_logging(verbosity)

    udp_sock = establish_udp_socket_to_remote_server()
    logging.info(f"{addr}: UDP connection to remote server established successfully")

    # Using select in a loop, we'll check if there's anything to read from remote server and put in the response_queue
    # or if we need to send anything from request_queue to the remote server,
    try:
        while True:
            input_ready, output_ready, _ = select([udp_sock], [udp_sock], [])
            for s in input_ready:
                packet = s.recvfrom(UDP_RCV_BUFFER_SIZE)
                response_queue.put(packet)
                logging.info(f"{addr}: Packet received from server and was put in the response queue.")
            for s in output_ready:
                try:
                    packet = request_queue.get_nowait()
                    s.sendto(packet, server_addr)
                    logging.info(f"{addr}: Packet sent to remote server @ {server_addr}.")
                except queue.Empty:
                    pass

    except (KeyboardInterrupt, ConnectionError) as e:
        logging.warning(f"{addr}: Closing the connection to remote server because of {e}")
        udp_sock.close()
        return


def handle_client(tcp_sock: socket.socket, addr, verbosity):
    configure_logging(verbosity)
    logging.info(f"{addr}: New TCP Connection established")
    try:
        # SSL wrap the socket
        sock = ssl.wrap_socket(tcp_sock, server_side=True, certfile='cert.pem', keyfile='key.pem')
        # Get the address of the remote server
        remote_address_message = sock.recv(TCP_RCV_BUFFER_SIZE).decode().split(',')
        if remote_address_message[0] != 'REMOTE':
            logging.error("First message from XClient must be the address for remote server")
            sock.sendall(b"First message from XClient must be the address for remote server")
            sock.close()
            return
        sock.send(b"OK")

        # Create the queues
        response_queue = Queue()
        request_queue = Queue()

        # Establish the UDP connection to remote server
        remote_address = (remote_address_message[1], int(remote_address_message[2]))

        # Start a new process for each UDP connection to the remote server to send to and receive from it.
        # Communications will be done by response/request queues
        remote_process = mp.Process(target=handle_remote_server,
                                    args=(remote_address, request_queue, response_queue, addr, verbosity))
        remote_process.start()

        # Listen to the TCP Connection for client requests
        while True:
            input_ready, output_ready, _ = select([sock], [sock], [])
            for s in input_ready:
                packet = s.recv(TCP_RCV_BUFFER_SIZE)
                if not packet:
                    logging.warning(f"{addr}: Connection closed!")
                    remote_process.kill()
                    sock.close()
                    return

                logging.info(f"{addr}: got a packet from TCP tunnel -> {packet}\n")
                request_queue.put(packet)
            for s in output_ready:
                try:
                    packet, _ = response_queue.get_nowait()
                    logging.info(f"{addr}: got response packet from queue, sending it to client now -> {packet}")
                    s.sendall(packet)
                except queue.Empty:
                    pass

    except KeyboardInterrupt:
        logging.warning("Closing socket")
        sock.close()
        return
    except ConnectionError as e:
        logging.error(e)
        sock.close()
        return
    except Exception as e:
        logging.error(f"This error happened! -> {e}")
        raise e


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
            logging.FileHandler("logs/XServer.log"),
            logging.StreamHandler()
        ]
    )


def main():
    args = parse_input_argument()
    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    configure_logging(args.verbosity)

    tcp_sock = init_socket(tcp_server_ip, tcp_server_port)
    try:
        while True:
            sock, addr = tcp_sock.accept()
            # Handle each TCP Connection on a separate process! could've used threads too.
            mp.Process(target=handle_client, args=(sock, addr, args.verbosity)).start()
    except KeyboardInterrupt:
        logging.info("Goodbye!")


if __name__ == '__main__':
    main()
    # sock = init_socket('127.0.0.1', 1771)
    # sock.accept()
