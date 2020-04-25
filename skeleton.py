import socket
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    return str(raw_ip_addr[0]) + '.' + str(raw_ip_addr[1]) + '.' + str(raw_ip_addr[2]) + '.' + str(raw_ip_addr[3])


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    segments = struct.unpack('!HHLLBBHHH', ip_packet_payload[0:20])

    src_port = segments[0]
    dest_port = segments[1]
    offset = segments[4] >> 4

    payload_start = 4 * offset
    data = ip_packet_payload[payload_start:]

    try:
        data.decode('utf-8')
        return TcpPacket(
            src_port=src_port,
            dst_port=dest_port,
            data_offset=offset,
            payload=data
        )
    except UnicodeError:
        return TcpPacket(
            src_port=src_port,
            dst_port=dest_port,
            data_offset=offset,
            payload=data
        )


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    version_and_ihl = ip_packet[0]
    ihl = version_and_ihl & 15

    length_of_header = ihl * 4
    # protocol, source, destination = struct.unpack('!2x4s4s', ip_packet[:20])

    protocol = ip_packet[9:10]
    source = ip_packet[12:16]
    destination = ip_packet[16:20]

    # formatting source and destination addresses in correct format
    source = str(source[0]) + '.' + str(source[1]) + '.' + str(source[2]) + '.' + str(source[3])
    destination = str(destination[0]) + '.' + str(destination[1]) + '.' + str(destination[2]) + '.' + str(
        destination[3])

    return IpPacket(protocol=protocol,
                    ihl=ihl,
                    source_address=source,
                    destination_address=destination,
                    payload=ip_packet[length_of_header:])


def snapshot(ip_object: IpPacket, tcp_object: TcpPacket):
    print(f"|| source: {ip_object.source_address} & port: {tcp_object.src_port}")
    print(f"|| destination: {ip_object.destination_address} & port: {tcp_object.dst_port}")
    print(f"|| data: {tcp_object.payload}")
    print("*" * 20)


def main():
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, 0x0006)
    while True:
        packet, address = stealer.recvfrom(4096)
        ip_packet = parse_network_layer_packet(packet)
        tcp_packet = parse_application_layer_packet(ip_packet.payload)
        snapshot(ip_packet, tcp_packet)


if __name__ == "__main__":
    main()
