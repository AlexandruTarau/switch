1 2 3
# Switch

This project simulates a simple switch with **VLAN tagging** and **Spanning Tree Protocol (STP)**, allowing switching functionality over interconnected networks.

## Project Structure

- **`main`**: Entry point to initialize switch parameters, read configuration, BPDU generation, frame processing and routing logic.
#### BPDU Processing
If it is BPDU, the frame is parsed using `parse_bpdu(data)`, extracting: the root bridge ID from the incoming BPDU, the path cost to the root reported by the sender, the sending bridge and port identifiers.

If received_root_bridge_id is smaller than the current root_bridge_id, a new bridge has been found with a lower ID, so we update it and the root_path_cost.

If the switch was previously the root bridge, it transitions to a non-root bridge role. All other trunk ports, except the root_port, are set to a "BLOCKING" state to prevent forwarding and loops.

The switch checks if its root_port is blocked. If so, it sets it as "DESIGNATED", enabling data forwarding and preventing loops.

The switch forwards BPDUs to other trunk ports to propagate updated root bridge information throughout the network. This new BPDU is created using the updated bridge id and path cost.

If the bridge root id received matches the current bridge root id, the switch updates its root_path_cost if it is provided a more efficient path or non-root ports are updated as "DESIGNATED" if the cost is greater than root_path_cost.

If the incoming BPDU's bridge id matches the switch's own bridge id, it sets the port to "BLOCKING".

If the switch is currently the root bridge, it makes all trunk ports "DESIGNATED", allowing traffic forwarding.

#### VLAN & Forwarding
If the received packet's port is not of type trunk, if the VLAN ID is not set, we set it and create the VLAN tag. If the VLAN ID is set but is not equal to the destination port VLAN ID, we drop the packet.

The connection is saved in the mac table.
If the destination is unicast, the switch checks if it is already in the mac table. If yes and the destination port is a trunk, we forward the packet with the VLAN tag and if the destination VLAN id is actually the source VLAN id, we forward the packet after removing the VLAN tag. If the destination is not in the mac table or it is multicast, the switch broadcasts the packet through all ports.

- **`parse_ethernet_header`**: Parses the Ethernet frame header to extract source and destination MAC, EtherType, and optional VLAN tag.
- **`create_bpdu`**: Constructs Bridge Protocol Data Units (BPDU) to be exchanged with other switches for STP calculations.
- **`send_bdpu_every_sec`**: Continuously sends BPDUs every second from the root bridge to prevent loops.
- **`parse_bpdu`**: Parses received BPDUs and returns desired information about the packet.
- **`mac_table`**: Maps source MACs to interfaces, allowing forwarding decisions based on known destinations.
- **`port_table`**: Tracks port configurations, including VLANs and STP port roles (blocking or designated).
