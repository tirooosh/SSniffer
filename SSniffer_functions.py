import re

import nmap
import pyshark
import psutil
import threading
import asyncio
# import re
# from urllib.parse import unquote
import dns.resolver
import dns.reversename
from functools import lru_cache


def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    print("Available network interfaces:")
    for index, (interface, addresses) in enumerate(interfaces.items()):
        print(f"{index}. Interface: {interface}")
    return list(interfaces.keys())


@lru_cache(maxsize=1024)  # Cache up to 1024 IP-to-hostname resolutions
def resolve_ip(ip):
    try:
        addr = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(addr, "PTR")
        hostname = str(answer[0])[:-1]  # Remove trailing dot
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        hostname = 'Unknown'
    except Exception as e:
        print(f"An error occurred: {e}")
        hostname = 'Unknown'
    return hostname


def return_port(st, packet):
    if 'TCP' in packet:
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport
    elif 'UDP' in packet:
        src_port = packet.udp.srcport
        dst_port = packet.udp.dstport

    if st == "src":
        return src_port
    else:
        return dst_port


def is_payload_readable(payload):
    try:
        # Attempt to convert payload from hex to ASCII
        ascii_payload = hex_to_ascii(payload)
        # Use regex to check if the ASCII conversion consists mainly of readable text
        # Here we're looking for a substantial portion of the string to be alphanumeric characters,
        # which suggests the payload is meaningful text.
        readable_text_ratio = len(re.findall(r'[a-zA-Z0-9\s,.!?;:]', ascii_payload)) / len(ascii_payload)
        return readable_text_ratio > 0.7  # You can adjust the threshold based on your needs
    except Exception:
        return False


def capture_packets(interface, packet_details, stop_event):
    print(f"Silently capturing packets on interface: {interface}...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface)
    try:
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                break

            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                payload_present = False
                payload_readable = False

                if 'TCP' in packet and hasattr(packet.tcp,
                                               'payload') and packet.tcp.payload and packet.tcp.payload != "00":
                    payload_present = True
                    payload_readable = is_payload_readable(packet.tcp.payload)

                elif 'UDP' in packet and hasattr(packet.udp,
                                                 'payload') and packet.udp.payload and packet.udp.payload != "00":
                    payload_present = True
                    payload_readable = is_payload_readable(packet.udp.payload)

                if payload_present:
                    key = f"{src_ip}({resolve_ip(src_ip)}) <-> {dst_ip}({resolve_ip(dst_ip)})"
                    with threading.Lock():
                        if key not in packet_details:
                            packet_details[key] = {'readable': [], 'encrypted': []}
                        if payload_readable:
                            packet_details[key]['readable'].append(packet)
                        else:
                            packet_details[key]['encrypted'].append(packet)
    finally:
        print("Stopped capturing packets.")
        loop.close()


def detailed_packet_info(packet_list):
    for index, packet in enumerate(packet_list, 1):
        src_host = resolve_ip(packet.ip.src)
        dst_host = resolve_ip(packet.ip.dst)
        protocol_info = packet.highest_layer if hasattr(packet, 'highest_layer') else "N/A"
        length_info = packet.length if hasattr(packet, 'length') else "N/A"
        print(
            f"{index}. From {src_host} ({packet.ip.src}) to {dst_host} ({packet.ip.dst}), Protocol: {protocol_info}, Length: {length_info}")

    detail_index = input("\nEnter the packet number to view details or 'exit' to return: ")
    if detail_index.isdigit():
        packet_index = int(detail_index) - 1
        if 0 <= packet_index < len(packet_list):
            show_packet_content(packet_list[packet_index])
        else:
            print("Invalid packet index.")
    elif detail_index.lower() == 'exit':
        return
    else:
        print("Invalid input. Please enter a number or 'exit'.")


def show_packet_content(packet):
    detail_str = "\nDetailed Packet Information:\n\n"

    try:
        source_info = f"Source IP: {packet.ip.src} ({resolve_ip(packet.ip.src)})"
        destination_info = f"Destination IP: {packet.ip.dst} ({resolve_ip(packet.ip.dst)})"
        detail_str += f"{source_info}\n{destination_info}\n\n"
    except AttributeError:
        detail_str += "IP information not available.\n"

    try:
        protocol = packet.transport_layer
        layer = packet[protocol.lower()]
        protocol_info = f"Transport Layer Protocol: {protocol}"
        detail_str += f"{protocol_info}\n\n"
    except AttributeError:
        detail_str += "Unsupported transport layer or transport layer not available.\n"
        return detail_str

    ip_address = str(packet.ip.src)
    port_number = str(return_port("src", packet))
    service = scan_port(ip_address, port_number)
    detail_str += f"Source Port {port_number} is used for: {service}\n"

    ip_address = str(packet.ip.dst)
    port_number = str(return_port("dst", packet))
    service = scan_port(ip_address, port_number)
    detail_str += f"Destination Port {port_number} is used for: {service}\n\n"

    if hasattr(layer, 'payload'):
        payload = layer.payload
        detail_str += f"\nThe payload is {payload}\n"
        try:
            translated_payload = hex_to_ascii(payload)
            detail_str += f"With translation, it is: {translated_payload}\n"
            temp_str = f"ai says: \n{asko_llama(translated_payload)}\n"
            detail_str += format_text_with_newlines(temp_str, 100)
        except Exception as e:
            detail_str += f"Error decoding payload: {e}\n"
    else:
        detail_str += "Payload not available for this packet.\n"
    print(detail_str)
    return detail_str


def format_text_with_newlines(text, chars_per_line):
    words = text.split()
    formatted_text = ""
    current_line = ""
    current_length = 0

    for word in words:
        # If adding the next word would exceed the line length, start a new line
        if current_length + len(word) + 1 > chars_per_line:
            formatted_text += current_line.strip() + "\n"
            current_line = word + " "
            current_length = len(word) + 1
        else:
            current_line += word + " "
            current_length += len(word) + 1

    # Add the last line
    if current_line:
        formatted_text += current_line.strip()

    return formatted_text



def scan_port(ip, port):
    try:
        # Create a scanner object
        nm = nmap.PortScanner()

        # Scan the specified port
        nm.scan(ip, str(port), arguments='-sS')

        # Check if the host is up
        if ip in nm.all_hosts():
            # Check if the port is in the scan result
            if port in nm[ip]['tcp']:
                # Get the result for the specific host and port
                port_info = nm[ip]['tcp'][port]

                # Extracting the service name
                service_name = port_info['name']
                return service_name
            else:
                return f"Port {port} not found in scan results."
        else:
            return f"Host {ip} not found in scan results."

    except nmap.PortScannerError as e:
        return f"PortScannerError: {e}"
    except Exception as e:
        return f"Error: {e}"


def hex_to_ascii(hex_string):
    # Remove colons from the hex string
    hex_string = hex_string.replace(":", "")
    # Convert hex string to bytes
    bytes_object = bytes.fromhex(hex_string)
    # Convert bytes to ASCII string
    ascii_string = bytes_object.decode("ascii", errors="replace")
    return ascii_string


def user_interaction(packet_details, stop_event):
    while not stop_event.is_set():
        cmd = input(
            "Enter 'summary' to see a summary of readable and encrypted packets, 'readable' to view readable packets, "
            "'encrypted' to view encrypted packets, 'stop' to quit capturing, 'exit' to quit program: ").strip().lower()

        if cmd == 'summary':
            print_summary(packet_details)
        elif cmd == 'readable' or cmd == 'encrypted':
            print_packet_type_summary(packet_details, readable=(cmd == 'readable'))
        elif cmd == 'stop':
            stop_event.set()
        elif cmd == 'exit':
            stop_event.set()
            break
        else:
            print("Invalid command. Please enter 'summary', 'readable', 'encrypted', 'stop', or 'exit'.")


def print_packet_type_summary(packet_details, readable=True):
    if packet_details:
        print("Summary of captured packets:")
        sorted_details = sorted(packet_details.items(),
                                key=lambda item: len(item[1]['readable' if readable else 'encrypted']), reverse=True)
        for index, (key, packets) in enumerate(sorted_details, 1):
            packet_count = len(packets['readable' if readable else 'encrypted'])
            print(f"{index}. {key}: {packet_count} {'readable' if readable else 'potentially encrypted'} packets")

        # Let user choose which type of packets to view immediately after summary
        index = int(input("Select the index to view packets: ")) - 1
        if index >= 0 and index < len(sorted_details):
            key, packets = sorted_details[index]
            print(f"Selected stream between {key}:")
            detailed_packet_info(packets['readable' if readable else 'encrypted'])
        else:
            print("Invalid index selected.")
    else:
        print("No packets captured.")


def print_summary(packet_details):
    if packet_details:
        print("Summary of captured packets:")
        sorted_details = sorted(packet_details.items(),
                                key=lambda item: len(item[1]['readable']) + len(item[1]['encrypted']), reverse=True)
        for index, (key, packets) in enumerate(sorted_details, 1):
            readable_packets = packets['readable']
            encrypted_packets = packets['encrypted']
            print(
                f"{index}. {key}: {len(readable_packets)} readable, {len(encrypted_packets)} potentially encrypted packets")
        # User selection for details
        index = int(input("Select the index to view packets: ")) - 1
        if index >= 0 and index < len(sorted_details):
            key, packets = sorted_details[index]
            print(f"Selected stream between {key}:")
            print("1. View readable packets")
            print("2. View potentially encrypted packets")
            sub_choice = input("Choose an option (1 for readable, 2 for encrypted): ")
            if sub_choice == '1':
                detailed_packet_info(readable_packets)
            elif sub_choice == '2':
                detailed_packet_info(encrypted_packets)
        else:
            print("Invalid index selected.")
    else:
        print("No packets captured.")


import ollama


def asko_llama(question):
    preview = "youre used as an ai for a school project of main your answers are straghtly fed to the user so dont add anything more. please describe me the perpose of that packet payload ignore all decrypted parts and answer with 1 line. if you dont know somthing its okay just say you cant undestand the payload at all. the payload is:"
    response = ollama.generate(model='llama3', prompt=str(preview + question))
    return (response['response'])


def run():
    print("Listing network interfaces...")
    interfaces = list_network_interfaces()
    interface_index = int(input("Select the interface index to capture packets: "))
    selected_interface = interfaces[interface_index]

    packet_details = {}
    stop_event = threading.Event()

    capture_thread = threading.Thread(target=capture_packets, args=(selected_interface, packet_details, stop_event))
    interaction_thread = threading.Thread(target=user_interaction, args=(packet_details, stop_event))

    capture_thread.start()
    interaction_thread.start()

    capture_thread.join()
    interaction_thread.join()


if __name__ == '__main__':
    run()
