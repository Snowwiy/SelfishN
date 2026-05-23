# Network discovery architecture

## Current SelfishNet flow

SelfishNet originally discovers devices from a single selected Windows `NetworkInterface`.

1. `CAdapter` asks the user to choose one active adapter, previously only adapters with a gateway.
2. `ArpForm.NicIsSelected` creates one `CArp` instance for that adapter.
3. `CArp.startArpListener` opens the adapter through PcapNet/WinPcap/Npcap and applies the `arp` capture filter.
4. `CArp.startArpDiscovery` enumerates the selected adapter's IPv4 subnet and sends ARP requests with `findMac`.
5. ARP replies are decoded by `arpListener` and inserted into `PcList`.
6. Bandwidth control uses ARP spoofing and packet forwarding on that same adapter. `startRedirector` captures `ip` packets and forwards packets between the victim and router while applying upload/download caps.

The original code does not query router client tables, does not inspect Windows routes beyond the selected adapter gateway, and does not scan subnets outside the selected adapter's local broadcast domain.

## Why guest Wi-Fi clients can be invisible

Most home routers implement guest Wi-Fi as a separate layer-2 broadcast domain, often backed by a VLAN, NAT segment, or firewall policy. A PC connected by Ethernet to the main LAN usually cannot see guest ARP broadcasts, guest ARP replies, mDNS/NetBIOS broadcasts, or switched unicast traffic. Promiscuous mode on the Ethernet adapter does not cross a VLAN, NAT boundary, or router firewall.

This means ARP-only discovery can see main LAN peers but cannot see guest clients unless the router bridges the guest SSID into the same L2 network or the PC also has an interface on that guest network. If the router allows routing from LAN to guest, layer-3 probes such as ICMP may detect guest IPs, but MAC addresses and ARP spoof-based bandwidth control still cannot work across the routed boundary.

## New discovery flow

The enhanced discovery keeps the existing ARP spoof/capture path intact and adds a separate `NetworkDiscoveryEngine`:

1. Enumerate all Windows network interfaces, including Ethernet, Wi-Fi, virtual, bridged, tunnel, and secondary adapters.
2. Report whether each adapter appears in the Npcap/WinPcap device list.
3. Build scan targets from directly connected IPv4 subnets on active adapters.
4. Optionally add route-table-derived private networks when guest discovery mode is enabled.
5. Accept user-provided custom CIDR, range, or single-host targets from the advanced panel.
6. Send best-effort SSDP, mDNS, and NetBIOS probes.
7. Parse the Windows ARP cache before and after probing.
8. Use local ARP scans for directly connected targets.
9. Use ICMP sweeps for route/custom/guest targets.
10. Add discovered devices to the existing `PcList`.

Devices discovered outside the selected adapter's controllable layer-2 segment are marked discovery-only so existing bandwidth limiting and spoofing behavior are not broken.

## Remaining limits

SelfishNet can discover a guest client only when the host has a usable path to it:

- Same broadcast domain: ARP discovery and bandwidth control can work.
- PC has a second interface on guest Wi-Fi: discovery can work on that interface; control requires selecting that interface and a gateway.
- Router routes LAN to guest and permits probes: ICMP/custom subnet discovery may show IP-only devices.
- Guest VLAN/NAT/firewall/client isolation blocks LAN-to-guest traffic: software on the LAN PC cannot discover or control those devices without router support, credentials/API access, a mirror port, or joining the guest network.

ARP spoofing cannot limit devices behind a router/NAT boundary because their traffic does not traverse the selected Ethernet adapter at layer 2.
