#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}
port_table = {}
root_bridge_id = 0
own_bridge_id = 0
root_path_cost = 0
root_port = -1

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu(root_bridge_id: int, sender_bridge_id: int, sender_path_cost: int, src_mac, dest_mac, port_id: int):
    # Changed the initial structure because root_bridge_id and sender_bridge_id are ints
    llc_length = 26
    llc_header = b'\x42\x42\x03'
    bpdu_header = b'\x00\x00\x00\x00'
    bpdu_config = b''.join([b'\x00', root_bridge_id.to_bytes(2, "big"), sender_path_cost.to_bytes(4, "big"),
                            sender_bridge_id.to_bytes(2, "big"), port_id.to_bytes(2, "big"), b'\x00\x01',
                            b'\x00\x14', b'\x00\x01', b'\x00\x0f'])
    return b''.join(
        [
            bytes.fromhex(dest_mac.replace(":", "")),
            bytes.fromhex(src_mac.replace(":", "")),
            llc_length.to_bytes(2, "big"),
            llc_header,
            bpdu_header,
            bpdu_config
        ]
    )

def send_bdpu_every_sec():
    while True:  
        if own_bridge_id == root_bridge_id:
            for interface in port_table:
                bpdu = create_bpdu(own_bridge_id, own_bridge_id, root_path_cost,
                        ':'.join(f'{b:02x}' for b in get_switch_mac()),
                        "01:80:c2:00:00:00", interface)
                send_to_link(interface, len(bpdu), bpdu)
        time.sleep(1)  # Send every second

def read_config(switch_id):
    try:
        with open(f'configs/switch{switch_id}.cfg', 'r') as file:
            lines = file.readlines()
    
        # Fill the VLAN table, map between port and vlan id
        key = 0
        for line in lines[1:]:
            _, value = line.strip().split()
            if value == 'T':
                port_table[key] = (value, "BLOCKING")
            else:
                port_table[key] = (value, "DESIGNATED")
            key += 1
        return lines[0]
    except FileNotFoundError:
        print("File not found!")

def is_unicast(dest_mac):
    first_byte = int(dest_mac.split(":")[0], 16)
    return (first_byte & 1) == 0

def is_bpdu(dest_mac):
    # Verifică dacă adresa MAC destinată este pentru BPDUs
    return dest_mac == '01:80:c2:00:00:00'

def parse_bpdu(data):
    dest_mac = ':'.join(f'{b:02x}' for b in data[0:6])
    src_mac = ':'.join(f'{b:02x}' for b in data[6:12])

    # BPDU Config fields we need
    root_bridge_id = int.from_bytes(data[22:24], "big")
    root_path_cost = int.from_bytes(data[24:28], "big")
    bridge_id = int.from_bytes(data[28:30], "big")
    port_id = int.from_bytes(data[30:32], "big")

    return (src_mac, dest_mac, root_bridge_id, root_path_cost, bridge_id, port_id)

def is_designated_port(sender_bridge_id, sender_port_id, receiver_bridge_id, receiver_port_id):
    if receiver_bridge_id < sender_bridge_id:
        return True
    elif receiver_bridge_id == sender_bridge_id:
        return receiver_port_id <= sender_port_id
    return False

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global mac_table
    global port_table
    global root_port

    # Init
    own_bridge_id = int(read_config(switch_id))
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            if port_table[i][0] == 'T':
                port_table[i] = (port_table[i][0], "DESIGNATED")

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        if is_bpdu(dest_mac):
            # Parse the BPDU frame
            src_mac, dest_mac, received_root_bridge_id, sender_path_cost, sender_bridge_id, sender_port_id = parse_bpdu(data)

            if received_root_bridge_id < root_bridge_id:
                we_were_the_root_bridge = root_bridge_id == own_bridge_id

                # Update root bridge id, root path cost and root port
                root_bridge_id = received_root_bridge_id
                root_path_cost = sender_path_cost + 10
                root_port = interface

                # Block all non-root ports
                if we_were_the_root_bridge:
                    for i in interfaces:
                        if i != root_port and port_table[i][0] == 'T':
                            port_table[i] = (port_table[0], "BLOCKING")
                
                # Set root to designated if blocked
                if port_table[root_port][1] == "BLOCKING":
                    port_table[root_port] = (port_table[root_port][0], "DESIGNATED")
                
                # Update and forward BPDU to all other trunk ports
                sender_bridge_id = own_bridge_id
                sender_path_cost = root_path_cost

                for i in interfaces:
                    if port_table[i][0] == 'T' and i != interface and port_table[i][1] != "BLOCKING":
                        bpdu = create_bpdu(received_root_bridge_id, sender_bridge_id, sender_path_cost,
                                        src_mac, dest_mac, interface)
                        send_to_link(i, len(bpdu), bpdu)

            elif received_root_bridge_id == root_bridge_id:
                if interface == root_port and sender_path_cost + 10 < root_path_cost:
                    root_path_cost = sender_path_cost + 10
                elif interface != root_port:
                    if sender_path_cost > root_path_cost:
                        if is_designated_port(sender_bridge_id, sender_port_id, own_bridge_id, interface):
                            port_table[interface] = (port_table[interface][0], "DESIGNATED")

            elif sender_bridge_id == own_bridge_id:
                port_table[interface] = (port_table[interface][0], "BLOCKING")

            if own_bridge_id == root_bridge_id:
                for i in interfaces:
                    if port_table[i][0] == 'T':
                        port_table[i] = (port_table[i][0], "DESIGNATED")
            continue

        # Adding VLAN tag
        if port_table[interface][0] != 'T':
            if vlan_id == -1:
                vlan_id = int(port_table[interface][0])
                data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                length += 4
            elif vlan_id != int(port_table[interface][0]):
                continue  # We drop the packet if the frame VLAN is different than dest port VLAN

        mac_table[src_mac] = (interface, vlan_id)
        
        # Forwarding
        if is_unicast(dest_mac):
            if dest_mac in mac_table:
                dest_interface, dest_vlan_id = mac_table[dest_mac]

                if port_table[dest_interface][0] == 'T':  # Destination is a switch
                    send_to_link(dest_interface, length, data)
                elif dest_vlan_id == vlan_id:
                    data = data[0:12] + data[16:]  # Remove the 802.1Q header
                    send_to_link(dest_interface, length - 4, data)
            else:
                for i in interfaces:
                    if i != interface:
                        if port_table[i][0] == str(vlan_id):
                            send_data = data[0:12] + data[16:]  # Remove the 802.1Q header
                            send_to_link(i, length - 4, send_data)
                        elif port_table[i][0] == 'T':
                            send_to_link(i, length, data)
        else:
            for i in interfaces:
                if i != interface:
                    if port_table[i][0] == str(vlan_id):
                        send_data = data[0:12] + data[16:]  # Remove the 802.1Q header
                        send_to_link(i, length - 4, send_data)
                    elif port_table[i][0] == 'T':
                        send_to_link(i, length, data)
        
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
