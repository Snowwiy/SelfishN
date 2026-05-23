using PcapNet;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SelfishNetv3
{
#pragma warning disable
    public class NetworkDiscoveryOptions
    {
        public NetworkInterface SelectedInterface;
        public bool SelectedInterfaceHasGateway;
        public bool GuestDetectionMode;
        public bool ForceLargeScans;
        public string CustomSubnets;
        public int MaxHostsPerSubnet = 1024;
        public int PingTimeoutMs = 200;
    }

    public class NetworkDiscoveryResult
    {
        public List<DiscoveredDevice> Devices = new List<DiscoveredDevice>();
        public List<NetworkAdapterInfo> Adapters = new List<NetworkAdapterInfo>();
        public List<string> Diagnostics = new List<string>();

        private Dictionary<string, DiscoveredDevice> devicesByIp = new Dictionary<string, DiscoveredDevice>();

        public void AddDevice(DiscoveredDevice device)
        {
            if (device == null || device.IP == null)
            {
                return;
            }

            string key = device.IP.ToString();
            if (devicesByIp.ContainsKey(key))
            {
                DiscoveredDevice existing = devicesByIp[key];
                if (!NetworkDiscoveryEngine.HasUsableMac(existing.Mac) && NetworkDiscoveryEngine.HasUsableMac(device.Mac))
                {
                    existing.Mac = device.Mac;
                }
                existing.CanRedirect = existing.CanRedirect || device.CanRedirect;
                if (!string.IsNullOrEmpty(device.Source) && existing.Source.IndexOf(device.Source) < 0)
                {
                    existing.Source = existing.Source + ", " + device.Source;
                }
                return;
            }

            devicesByIp.Add(key, device);
            Devices.Add(device);
        }
    }

    public class DiscoveredDevice
    {
        public IPAddress IP;
        public PhysicalAddress Mac;
        public string Source;
        public bool CanRedirect;
    }

    public class NetworkAdapterInfo
    {
        public NetworkInterface Interface;
        public string Id;
        public string Name;
        public string Description;
        public NetworkInterfaceType Type;
        public OperationalStatus Status;
        public PhysicalAddress Mac;
        public bool IsPcapVisible;
        public List<IPAddress> IPv4Addresses = new List<IPAddress>();
        public List<IPAddress> IPv4Masks = new List<IPAddress>();
        public List<IPAddress> Gateways = new List<IPAddress>();
        public List<IPv4ScanTarget> DirectTargets = new List<IPv4ScanTarget>();

        public bool IsUp
        {
            get { return Status == OperationalStatus.Up; }
        }

        public bool HasIPv4
        {
            get { return IPv4Addresses.Count > 0; }
        }

        public bool HasGateway
        {
            get { return Gateways.Count > 0; }
        }

        public string DisplayName
        {
            get
            {
                string ip = HasIPv4 ? IPv4Addresses[0].ToString() : "no IPv4";
                string gw = HasGateway ? "gw " + Gateways[0].ToString() : "no gateway";
                return Description + " (" + ip + ", " + gw + ")";
            }
        }
    }

    public class IPv4ScanTarget
    {
        public IPAddress StartAddress;
        public IPAddress EndAddress;
        public IPAddress NetworkAddress;
        public IPAddress Netmask;
        public IPAddress BroadcastAddress;
        public int PrefixLength;
        public string Source;
        public bool IsDirect;
        public bool IsCustom;
        public NetworkInterface Adapter;

        public ulong AddressCount
        {
            get
            {
                uint start = NetworkDiscoveryEngine.ToUInt32(StartAddress);
                uint end = NetworkDiscoveryEngine.ToUInt32(EndAddress);
                return (ulong)end - (ulong)start + 1UL;
            }
        }

        public string DisplayName
        {
            get
            {
                if (NetworkAddress != null && PrefixLength >= 0)
                {
                    return NetworkAddress + "/" + PrefixLength;
                }
                return StartAddress + "-" + EndAddress;
            }
        }

        public bool Contains(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            uint value = NetworkDiscoveryEngine.ToUInt32(address);
            return value >= NetworkDiscoveryEngine.ToUInt32(StartAddress) && value <= NetworkDiscoveryEngine.ToUInt32(EndAddress);
        }

        public List<IPAddress> EnumerateHosts(int maxHosts)
        {
            List<IPAddress> hosts = new List<IPAddress>();
            uint start = NetworkDiscoveryEngine.ToUInt32(StartAddress);
            uint end = NetworkDiscoveryEngine.ToUInt32(EndAddress);
            uint current = start;
            int count = 0;

            while (current <= end && count < maxHosts)
            {
                hosts.Add(NetworkDiscoveryEngine.FromUInt32(current));
                count++;
                if (current == UInt32.MaxValue)
                {
                    break;
                }
                current++;
            }

            return hosts;
        }
    }

    public class NetworkDiscoveryEngine
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint phyAddrLen);

        public NetworkDiscoveryResult Scan(NetworkDiscoveryOptions options)
        {
            if (options == null)
            {
                options = new NetworkDiscoveryOptions();
            }

            NetworkDiscoveryResult result = new NetworkDiscoveryResult();
            result.Diagnostics.Add("Discovery started " + DateTime.Now.ToString("u"));
            result.Adapters = GetAdapters(result.Diagnostics);

            List<IPv4ScanTarget> targets = BuildTargets(options, result.Adapters, result.Diagnostics);
            AddUdpDiscoveredDevices(result, targets, SendUdpDiscoveryProbes(targets, result.Diagnostics));
            AddArpCacheDevices(result, targets, options, "ARP cache before scan");

            foreach (IPv4ScanTarget target in targets)
            {
                if (ShouldSkipTarget(target, options, result.Diagnostics))
                {
                    continue;
                }

                if (target.IsDirect && options.ForceLargeScans)
                {
                    ScanDirectTargetWithArp(target, options, result);
                }
                else if (target.IsDirect)
                {
                    result.Diagnostics.Add("Skipped active ARP sweep for " + target.DisplayName + ": use Force scan for slower MAC-level probing.");
                }

                if (!target.IsDirect || target.IsCustom || options.GuestDetectionMode)
                {
                    PingSweep(target, options, result);
                }
            }

            AddArpCacheDevices(result, targets, options, "ARP cache after scan");
            result.Diagnostics.Add("Discovery finished. Devices found: " + result.Devices.Count);
            return result;
        }

        public static List<NetworkAdapterInfo> GetAdapters(List<string> diagnostics)
        {
            List<string> pcapIds = GetPcapDeviceIds(diagnostics);
            List<NetworkAdapterInfo> adapters = new List<NetworkAdapterInfo>();
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface nic in interfaces)
            {
                NetworkAdapterInfo info = new NetworkAdapterInfo();
                info.Interface = nic;
                info.Id = nic.Id;
                info.Name = nic.Name;
                info.Description = nic.Description;
                info.Type = nic.NetworkInterfaceType;
                info.Status = nic.OperationalStatus;
                info.Mac = nic.GetPhysicalAddress();
                info.IsPcapVisible = IsPcapVisible(nic, pcapIds);

                try
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    foreach (UnicastIPAddressInformation addressInfo in properties.UnicastAddresses)
                    {
                        if (addressInfo.Address.AddressFamily != AddressFamily.InterNetwork || addressInfo.IPv4Mask == null)
                        {
                            continue;
                        }

                        info.IPv4Addresses.Add(addressInfo.Address);
                        info.IPv4Masks.Add(addressInfo.IPv4Mask);
                        IPv4ScanTarget target = CreateTargetFromAddressAndMask(addressInfo.Address, addressInfo.IPv4Mask);
                        target.Source = "connected interface " + nic.Description;
                        target.IsDirect = true;
                        target.Adapter = nic;
                        info.DirectTargets.Add(target);
                    }

                    foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
                    {
                        if (gateway.Address.AddressFamily == AddressFamily.InterNetwork && !gateway.Address.Equals(IPAddress.Any))
                        {
                            info.Gateways.Add(gateway.Address);
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (diagnostics != null)
                    {
                        diagnostics.Add("Interface read failed for " + nic.Description + ": " + ex.Message);
                    }
                }

                adapters.Add(info);
            }

            if (diagnostics != null)
            {
                diagnostics.Add("Windows interfaces detected: " + adapters.Count);
                foreach (NetworkAdapterInfo adapter in adapters)
                {
                    diagnostics.Add(FormatAdapterDiagnostic(adapter));
                }
            }

            return adapters;
        }

        public static bool HasUsableMac(PhysicalAddress mac)
        {
            if (mac == null)
            {
                return false;
            }

            byte[] bytes = mac.GetAddressBytes();
            if (bytes.Length == 0)
            {
                return false;
            }

            bool allZero = true;
            bool allFF = true;
            for (int i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] != 0)
                {
                    allZero = false;
                }
                if (bytes[i] != 0xFF)
                {
                    allFF = false;
                }
            }

            return !allZero && !allFF;
        }

        public static uint ToUInt32(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        }

        public static IPAddress FromUInt32(uint value)
        {
            byte[] bytes = new byte[4];
            bytes[0] = (byte)((value >> 24) & 0xFF);
            bytes[1] = (byte)((value >> 16) & 0xFF);
            bytes[2] = (byte)((value >> 8) & 0xFF);
            bytes[3] = (byte)(value & 0xFF);
            return new IPAddress(bytes);
        }

        public static IPv4ScanTarget CreateTargetFromAddressAndMask(IPAddress address, IPAddress mask)
        {
            uint ip = ToUInt32(address);
            uint maskValue = ToUInt32(mask);
            uint network = ip & maskValue;
            uint broadcast = network | ~maskValue;
            ulong total = (ulong)broadcast - (ulong)network + 1UL;

            uint start = total > 2 ? network + 1 : network;
            uint end = total > 2 ? broadcast - 1 : broadcast;

            IPv4ScanTarget target = new IPv4ScanTarget();
            target.StartAddress = FromUInt32(start);
            target.EndAddress = FromUInt32(end);
            target.NetworkAddress = FromUInt32(network);
            target.Netmask = mask;
            target.BroadcastAddress = FromUInt32(broadcast);
            target.PrefixLength = PrefixLength(maskValue);
            return target;
        }

        public static bool TryParseTarget(string value, out IPv4ScanTarget target, out string error)
        {
            target = null;
            error = null;

            if (string.IsNullOrEmpty(value))
            {
                error = "empty target";
                return false;
            }

            value = value.Trim();
            if (value.IndexOf("-") > 0)
            {
                string[] parts = value.Split('-');
                if (parts.Length != 2)
                {
                    error = "range must contain one dash";
                    return false;
                }

                IPAddress start;
                IPAddress end;
                if (!IPAddress.TryParse(parts[0].Trim(), out start) || !IPAddress.TryParse(parts[1].Trim(), out end) ||
                    start.AddressFamily != AddressFamily.InterNetwork || end.AddressFamily != AddressFamily.InterNetwork)
                {
                    error = "range contains an invalid IPv4 address";
                    return false;
                }

                if (ToUInt32(start) > ToUInt32(end))
                {
                    error = "range start is greater than range end";
                    return false;
                }

                target = new IPv4ScanTarget();
                target.StartAddress = start;
                target.EndAddress = end;
                target.PrefixLength = -1;
                target.Source = "custom range";
                target.IsCustom = true;
                return true;
            }

            if (value.IndexOf("/") > 0)
            {
                string[] parts = value.Split('/');
                IPAddress network;
                int prefix;
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0].Trim(), out network) ||
                    network.AddressFamily != AddressFamily.InterNetwork || !Int32.TryParse(parts[1].Trim(), out prefix) ||
                    prefix < 0 || prefix > 32)
                {
                    error = "CIDR target must look like 192.168.50.0/24";
                    return false;
                }

                target = CreateTargetFromAddressAndMask(network, FromUInt32(PrefixToMask(prefix)));
                target.Source = "custom CIDR";
                target.IsCustom = true;
                return true;
            }

            IPAddress single;
            if (IPAddress.TryParse(value, out single) && single.AddressFamily == AddressFamily.InterNetwork)
            {
                target = new IPv4ScanTarget();
                target.StartAddress = single;
                target.EndAddress = single;
                target.NetworkAddress = single;
                target.Netmask = IPAddress.Parse("255.255.255.255");
                target.BroadcastAddress = single;
                target.PrefixLength = 32;
                target.Source = "custom host";
                target.IsCustom = true;
                return true;
            }

            error = "target is not an IPv4 CIDR, range, or host";
            return false;
        }

        private static string FormatAdapterDiagnostic(NetworkAdapterInfo adapter)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("Interface: ");
            builder.Append(adapter.Description);
            builder.Append(" | ");
            builder.Append(adapter.Status);
            builder.Append(" | ");
            builder.Append(adapter.Type);
            builder.Append(" | pcap=");
            builder.Append(adapter.IsPcapVisible ? "visible" : "not listed");
            builder.Append(" | IPv4=");
            builder.Append(JoinAddresses(adapter.IPv4Addresses));
            builder.Append(" | gateways=");
            builder.Append(JoinAddresses(adapter.Gateways));
            return builder.ToString();
        }

        private static string JoinAddresses(List<IPAddress> addresses)
        {
            if (addresses == null || addresses.Count == 0)
            {
                return "none";
            }

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < addresses.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append(", ");
                }
                builder.Append(addresses[i].ToString());
            }
            return builder.ToString();
        }

        private static List<IPv4ScanTarget> BuildTargets(NetworkDiscoveryOptions options, List<NetworkAdapterInfo> adapters, List<string> diagnostics)
        {
            Dictionary<string, IPv4ScanTarget> targetsByKey = new Dictionary<string, IPv4ScanTarget>();

            foreach (NetworkAdapterInfo adapter in adapters)
            {
                if (!adapter.IsUp || !adapter.HasIPv4)
                {
                    diagnostics.Add("Skipped interface " + adapter.Description + ": not up or no IPv4 address.");
                    continue;
                }

                foreach (IPv4ScanTarget target in adapter.DirectTargets)
                {
                    AddTarget(targetsByKey, target, options, diagnostics);
                }
            }

            if (options.GuestDetectionMode)
            {
                foreach (IPv4ScanTarget routeTarget in GetRouteTargets(diagnostics))
                {
                    AddTarget(targetsByKey, routeTarget, options, diagnostics);
                }
            }

            foreach (IPv4ScanTarget customTarget in ParseCustomTargets(options.CustomSubnets, diagnostics))
            {
                AddTarget(targetsByKey, customTarget, options, diagnostics);
            }

            List<IPv4ScanTarget> targets = new List<IPv4ScanTarget>(targetsByKey.Values);
            diagnostics.Add("Scan targets: " + targets.Count);
            foreach (IPv4ScanTarget target in targets)
            {
                diagnostics.Add("Target: " + target.DisplayName + " | source=" + target.Source + " | hosts=" + target.AddressCount);
            }
            return targets;
        }

        private static void AddTarget(Dictionary<string, IPv4ScanTarget> targetsByKey, IPv4ScanTarget target, NetworkDiscoveryOptions options, List<string> diagnostics)
        {
            if (target == null)
            {
                return;
            }

            if (!IsUsableUnicast(target.StartAddress))
            {
                diagnostics.Add("Skipped target " + target.DisplayName + ": not a usable unicast network.");
                return;
            }

            string key = target.StartAddress + "-" + target.EndAddress;
            if (!targetsByKey.ContainsKey(key))
            {
                targetsByKey.Add(key, target);
            }
            else if (options.SelectedInterface != null && target.Adapter != null && target.Adapter.Id == options.SelectedInterface.Id)
            {
                targetsByKey[key] = target;
            }
        }

        private static bool ShouldSkipTarget(IPv4ScanTarget target, NetworkDiscoveryOptions options, List<string> diagnostics)
        {
            if (target.AddressCount > (ulong)options.MaxHostsPerSubnet && !options.ForceLargeScans)
            {
                diagnostics.Add("Skipped " + target.DisplayName + ": " + target.AddressCount + " hosts exceeds limit " + options.MaxHostsPerSubnet + ".");
                return true;
            }

            if (!target.IsCustom && !IsPrivateOrLinkLocal(target.StartAddress))
            {
                diagnostics.Add("Skipped " + target.DisplayName + ": automatic scans are limited to private/link-local ranges.");
                return true;
            }

            return false;
        }

        private static List<IPv4ScanTarget> ParseCustomTargets(string customSubnets, List<string> diagnostics)
        {
            List<IPv4ScanTarget> targets = new List<IPv4ScanTarget>();
            if (string.IsNullOrEmpty(customSubnets))
            {
                return targets;
            }

            string[] entries = customSubnets.Split(new char[] { ',', ';', '\r', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string entry in entries)
            {
                IPv4ScanTarget target;
                string error;
                if (TryParseTarget(entry, out target, out error))
                {
                    targets.Add(target);
                }
                else
                {
                    diagnostics.Add("Skipped custom target '" + entry + "': " + error + ".");
                }
            }

            return targets;
        }

        private static List<IPv4ScanTarget> GetRouteTargets(List<string> diagnostics)
        {
            List<IPv4ScanTarget> targets = new List<IPv4ScanTarget>();
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("route", "print -4");
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.CreateNoWindow = true;

                Process process = Process.Start(startInfo);
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    string trimmed = line.Trim();
                    string[] parts = trimmed.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3)
                    {
                        continue;
                    }

                    IPAddress destination;
                    IPAddress mask;
                    if (!IPAddress.TryParse(parts[0], out destination) || !IPAddress.TryParse(parts[1], out mask) ||
                        destination.AddressFamily != AddressFamily.InterNetwork || mask.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }

                    if (destination.Equals(IPAddress.Any) || destination.Equals(IPAddress.Loopback))
                    {
                        continue;
                    }

                    IPv4ScanTarget target = CreateTargetFromAddressAndMask(destination, mask);
                    if (target.AddressCount <= 1)
                    {
                        continue;
                    }

                    target.Source = "Windows route table";
                    targets.Add(target);
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add("Route table inspection failed: " + ex.Message);
            }

            return targets;
        }

        private static void ScanDirectTargetWithArp(IPv4ScanTarget target, NetworkDiscoveryOptions options, NetworkDiscoveryResult result)
        {
            IPAddress source = null;
            if (target.Adapter != null)
            {
                NetworkAdapterInfo adapterInfo = null;
                foreach (NetworkAdapterInfo adapter in result.Adapters)
                {
                    if (adapter.Interface.Id == target.Adapter.Id)
                    {
                        adapterInfo = adapter;
                        break;
                    }
                }
                if (adapterInfo != null && adapterInfo.IPv4Addresses.Count > 0)
                {
                    source = adapterInfo.IPv4Addresses[0];
                }
            }

            List<IPAddress> hosts = target.EnumerateHosts(options.MaxHostsPerSubnet);
            if (target.AddressCount > (ulong)hosts.Count)
            {
                result.Diagnostics.Add("Limited " + target.DisplayName + " to first " + hosts.Count + " hosts for performance.");
            }
            result.Diagnostics.Add("ARP scanning " + target.DisplayName + " via " + (target.Adapter == null ? "unknown adapter" : target.Adapter.Description) + ".");

            int remaining = hosts.Count;
            if (remaining == 0)
            {
                return;
            }

            RaiseThreadPoolMinimum(hosts.Count);
            ManualResetEvent done = new ManualResetEvent(false);
            foreach (IPAddress host in hosts)
            {
                ThreadPool.QueueUserWorkItem(delegate(object state)
                {
                    IPAddress ip = (IPAddress)state;
                    try
                    {
                        PhysicalAddress mac = SendArp(ip, source);
                        if (HasUsableMac(mac))
                        {
                            DiscoveredDevice device = new DiscoveredDevice();
                            device.IP = ip;
                            device.Mac = mac;
                            device.Source = "ARP scan";
                            device.CanRedirect = CanRedirectFromTarget(target, options, mac);
                            lock (result)
                            {
                                result.AddDevice(device);
                            }
                        }
                    }
                    finally
                    {
                        if (Interlocked.Decrement(ref remaining) == 0)
                        {
                            done.Set();
                        }
                    }
                }, host);
            }

            done.WaitOne();
            done.Close();
        }

        private static void PingSweep(IPv4ScanTarget target, NetworkDiscoveryOptions options, NetworkDiscoveryResult result)
        {
            List<IPAddress> hosts = target.EnumerateHosts(options.MaxHostsPerSubnet);
            if (hosts.Count == 0)
            {
                return;
            }

            if (target.AddressCount > (ulong)hosts.Count)
            {
                result.Diagnostics.Add("Limited " + target.DisplayName + " ICMP scan to first " + hosts.Count + " hosts for performance.");
            }
            result.Diagnostics.Add("ICMP scanning " + target.DisplayName + " (" + hosts.Count + " hosts).");
            int remaining = hosts.Count;
            RaiseThreadPoolMinimum(hosts.Count);
            ManualResetEvent done = new ManualResetEvent(false);

            foreach (IPAddress host in hosts)
            {
                ThreadPool.QueueUserWorkItem(delegate(object state)
                {
                    IPAddress ip = (IPAddress)state;
                    try
                    {
                        Ping ping = new Ping();
                        PingReply reply = ping.Send(ip, options.PingTimeoutMs);
                        if (reply != null && reply.Status == IPStatus.Success)
                        {
                            DiscoveredDevice device = new DiscoveredDevice();
                            device.IP = ip;
                            device.Mac = PhysicalAddress.None;
                            device.Source = "ICMP";
                            device.CanRedirect = false;
                            lock (result)
                            {
                                result.AddDevice(device);
                            }
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        if (Interlocked.Decrement(ref remaining) == 0)
                        {
                            done.Set();
                        }
                    }
                }, host);
            }

            done.WaitOne();
            done.Close();
        }

        private static void RaiseThreadPoolMinimum(int hostCount)
        {
            int workerThreads;
            int completionPortThreads;
            ThreadPool.GetMinThreads(out workerThreads, out completionPortThreads);
            int desired = Math.Min(64, Math.Max(workerThreads, hostCount));
            if (desired > workerThreads)
            {
                ThreadPool.SetMinThreads(desired, completionPortThreads);
            }
        }

        private static PhysicalAddress SendArp(IPAddress destination, IPAddress source)
        {
            try
            {
                byte[] mac = new byte[6];
                uint len = (uint)mac.Length;
                int dest = BitConverter.ToInt32(destination.GetAddressBytes(), 0);
                int src = source == null ? 0 : BitConverter.ToInt32(source.GetAddressBytes(), 0);
                int result = SendARP(dest, src, mac, ref len);
                if (result == 0 && len > 0)
                {
                    byte[] actual = new byte[len];
                    Array.Copy(mac, actual, actual.Length);
                    return new PhysicalAddress(actual);
                }
            }
            catch
            {
            }

            return PhysicalAddress.None;
        }

        private static void AddArpCacheDevices(NetworkDiscoveryResult result, List<IPv4ScanTarget> targets, NetworkDiscoveryOptions options, string source)
        {
            Dictionary<IPAddress, PhysicalAddress> cache = ReadArpCache(result.Diagnostics);
            foreach (KeyValuePair<IPAddress, PhysicalAddress> entry in cache)
            {
                if (!IsInAnyTarget(entry.Key, targets) || !HasUsableMac(entry.Value))
                {
                    continue;
                }

                IPv4ScanTarget target = FindTargetForAddress(entry.Key, targets);
                DiscoveredDevice device = new DiscoveredDevice();
                device.IP = entry.Key;
                device.Mac = entry.Value;
                device.Source = source;
                device.CanRedirect = target != null && CanRedirectFromTarget(target, options, entry.Value);
                result.AddDevice(device);
            }
        }

        private static Dictionary<IPAddress, PhysicalAddress> ReadArpCache(List<string> diagnostics)
        {
            Dictionary<IPAddress, PhysicalAddress> cache = new Dictionary<IPAddress, PhysicalAddress>();
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("arp", "-a");
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.CreateNoWindow = true;

                Process process = Process.Start(startInfo);
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    string[] parts = line.Trim().Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                    {
                        continue;
                    }

                    IPAddress ip;
                    PhysicalAddress mac;
                    if (IPAddress.TryParse(parts[0], out ip) && TryParseMac(parts[1], out mac))
                    {
                        cache[ip] = mac;
                    }
                }
            }
            catch (Exception ex)
            {
                diagnostics.Add("ARP cache read failed: " + ex.Message);
            }

            diagnostics.Add("ARP cache entries parsed: " + cache.Count);
            return cache;
        }

        private static bool TryParseMac(string value, out PhysicalAddress mac)
        {
            mac = PhysicalAddress.None;
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            string clean = value.Replace("-", string.Empty).Replace(":", string.Empty);
            if (clean.Length != 12)
            {
                return false;
            }

            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                try
                {
                    bytes[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);
                }
                catch
                {
                    return false;
                }
            }

            mac = new PhysicalAddress(bytes);
            return true;
        }

        private static bool IsInAnyTarget(IPAddress address, List<IPv4ScanTarget> targets)
        {
            return FindTargetForAddress(address, targets) != null;
        }

        private static IPv4ScanTarget FindTargetForAddress(IPAddress address, List<IPv4ScanTarget> targets)
        {
            foreach (IPv4ScanTarget target in targets)
            {
                if (target.Contains(address))
                {
                    return target;
                }
            }
            return null;
        }

        private static bool CanRedirectFromTarget(IPv4ScanTarget target, NetworkDiscoveryOptions options, PhysicalAddress mac)
        {
            return target != null &&
                   target.IsDirect &&
                   target.Adapter != null &&
                   options.SelectedInterface != null &&
                   options.SelectedInterfaceHasGateway &&
                   target.Adapter.Id == options.SelectedInterface.Id &&
                   HasUsableMac(mac);
        }

        private static void AddUdpDiscoveredDevices(NetworkDiscoveryResult result, List<IPv4ScanTarget> targets, List<IPAddress> addresses)
        {
            foreach (IPAddress address in addresses)
            {
                if (!IsInAnyTarget(address, targets))
                {
                    continue;
                }

                DiscoveredDevice device = new DiscoveredDevice();
                device.IP = address;
                device.Mac = PhysicalAddress.None;
                device.Source = "UDP discovery";
                device.CanRedirect = false;
                result.AddDevice(device);
            }
        }

        private static List<IPAddress> SendUdpDiscoveryProbes(List<IPv4ScanTarget> targets, List<string> diagnostics)
        {
            List<IPAddress> responders = new List<IPAddress>();
            try
            {
                using (UdpClient udp = new UdpClient())
                {
                    udp.EnableBroadcast = true;
                    udp.Client.ReceiveTimeout = 750;
                    byte[] ssdp = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n");
                    udp.Send(ssdp, ssdp.Length, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));

                    byte[] mdns = BuildDnsQuery(new string[] { "_services", "_dns-sd", "_udp", "local" }, 12);
                    udp.Send(mdns, mdns.Length, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));

                    byte[] nbns = BuildNetBiosWildcardQuery();
                    foreach (IPv4ScanTarget target in targets)
                    {
                        if (target.BroadcastAddress != null && target.AddressCount <= 65534)
                        {
                            udp.Send(nbns, nbns.Length, new IPEndPoint(target.BroadcastAddress, 137));
                        }
                    }

                    DateTime waitUntil = DateTime.Now.AddMilliseconds(800);
                    while (DateTime.Now < waitUntil)
                    {
                        try
                        {
                            IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                            udp.Receive(ref remote);
                            if (remote.Address != null && remote.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                responders.Add(remote.Address);
                            }
                        }
                        catch (SocketException)
                        {
                            break;
                        }
                    }
                }

                diagnostics.Add("Sent SSDP, mDNS, and NetBIOS discovery probes. Responses: " + responders.Count);
            }
            catch (Exception ex)
            {
                diagnostics.Add("UDP discovery probes failed: " + ex.Message);
            }
            return responders;
        }

        private static byte[] BuildDnsQuery(string[] labels, ushort qtype)
        {
            List<byte> packet = new List<byte>();
            packet.AddRange(new byte[] { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (string label in labels)
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                packet.Add((byte)bytes.Length);
                packet.AddRange(bytes);
            }
            packet.Add(0);
            packet.Add((byte)((qtype >> 8) & 0xFF));
            packet.Add((byte)(qtype & 0xFF));
            packet.Add(0);
            packet.Add(1);
            return packet.ToArray();
        }

        private static byte[] BuildNetBiosWildcardQuery()
        {
            List<byte> packet = new List<byte>();
            packet.AddRange(new byte[] { 0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            string encodedWildcard = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            packet.Add(0x20);
            packet.AddRange(Encoding.ASCII.GetBytes(encodedWildcard));
            packet.Add(0x00);
            packet.AddRange(new byte[] { 0x00, 0x21, 0x00, 0x01 });
            return packet.ToArray();
        }

        private static List<string> GetPcapDeviceIds(List<string> diagnostics)
        {
            List<string> ids = new List<string>();
            try
            {
                CPcapNet pcap = new CPcapNet();
                ArrayList devices = pcap.getAllDevsID();
                if (devices != null)
                {
                    foreach (object device in devices)
                    {
                        if (device != null)
                        {
                            ids.Add(device.ToString());
                        }
                    }
                }
                pcap.Dispose();
                diagnostics.Add("Npcap/WinPcap devices detected: " + ids.Count);
            }
            catch (Exception ex)
            {
                diagnostics.Add("Npcap/WinPcap enumeration failed: " + ex.Message);
            }
            return ids;
        }

        private static bool IsPcapVisible(NetworkInterface nic, List<string> pcapIds)
        {
            foreach (string id in pcapIds)
            {
                if (id.IndexOf(nic.Id, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    id.IndexOf(nic.Id.Replace("{", string.Empty).Replace("}", string.Empty), StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsUsableUnicast(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            return bytes[0] != 0 && bytes[0] != 127 && bytes[0] < 224;
        }

        private static bool IsPrivateOrLinkLocal(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 10 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }

        private static int PrefixLength(uint mask)
        {
            int count = 0;
            for (int i = 31; i >= 0; i--)
            {
                if ((mask & (1U << i)) != 0)
                {
                    count++;
                }
            }
            return count;
        }

        private static uint PrefixToMask(int prefix)
        {
            if (prefix == 0)
            {
                return 0;
            }
            return UInt32.MaxValue << (32 - prefix);
        }
    }
#pragma warning restore
}
