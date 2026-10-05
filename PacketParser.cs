using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Network_Analyzer
{
    internal static class PacketParser
    {
        public static CapturedPacket ParsePacket(int number, RawCapture rawPacket)
        {
            Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data); 
            
            IPPacket ipPacket = packet.Extract<IPPacket>();
            IPv4Packet? ipv4 = packet.Extract<IPv4Packet>();
            IPv6Packet? ipv6 = packet.Extract<IPv6Packet>();
            TcpPacket? tcp = packet.Extract<TcpPacket>();
            UdpPacket? udp = packet.Extract<UdpPacket>();
            ArpPacket? arp = packet.Extract<ArpPacket>();
            IcmpV4Packet? icmpV4 = packet.Extract<IcmpV4Packet>();
            IcmpV6Packet? icmpV6 = packet.Extract<IcmpV6Packet>();
            Ieee8021QPacket? vlan = packet.Extract<Ieee8021QPacket>();
            LldpPacket? llDiscovery = packet.Extract<LldpPacket>();
            MacFrame? wifi = packet.Extract<MacFrame>();

            string protocol = "Unknown";
            string info = "";

            if (vlan != null)
            {
                info = "802.1Q VLAN traffic";
            }

            if (arp != null)
            {
                protocol = "ARP";
            }
            else if (llDiscovery != null)
            {
                protocol = "LLDP";
            }
            else if (icmpV4 != null)
            {
                protocol = "ICMPv4";
            }
            else if (icmpV6 != null)
            {
                protocol = "ICMPv6";
            }
            else if (tcp != null)
            {
                byte[] data = tcp.PayloadData;
                string text = Encoding.ASCII.GetString(data);
                if (data.Length >= 5 && data[0] >= 20 && data[0] <= 23 && data[1] == 0x03 && data[2] <= 0x04) //checks for TLS
                {
                    protocol = "HTTPS";
                } else if (text.StartsWith("GET ") || text.StartsWith("POST ") || text.StartsWith("PUT ") || text.StartsWith("DELETE ") || text.StartsWith("HTTP/"))
                {
                    protocol = "HTTP";
                } else if (text.StartsWith("USER ") || text.StartsWith("PASS ") || text.StartsWith("220 ") || text.StartsWith("230 ") || text.StartsWith("331 ") || tcp.SourcePort == 21 || tcp.DestinationPort == 21)
                {
                    protocol = "FTP";
                }
                else
                {
                    protocol = "TCP";
                }

            } else if (udp != null)
            {
                if (udp.SourcePort == 53 || udp.DestinationPort == 53)
                {
                    protocol = "DNS";
                } else
                {
                    protocol = "UDP";
                }
                
            }
            else if (ipv4 != null)
            {
                protocol = "IPv4";
            }
            else if (ipv6 != null)
            {
                protocol = "IPv6";
            }
            else if (wifi != null)
            {
                protocol = "802.11";
            }
            else if (vlan != null)
            {
                protocol = "VLAN";
            }

            return new CapturedPacket
            {
                Number = number,
                Timestamp = rawPacket.Timeval.Date,
                Source = ipPacket?.SourceAddress.ToString(),
                SourcePort = tcp?.SourcePort.ToString() ?? udp?.SourcePort.ToString(),
                Destination = ipPacket?.DestinationAddress.ToString(),
                DestinationPort = tcp?.DestinationPort.ToString() ?? udp?.DestinationPort.ToString(),
                Protocol = protocol,
                Length = rawPacket.Data.Length,
                Info = info,
                RawData = rawPacket.Data,
                OriginalPacket = rawPacket,
              
            };
        }
    }
}
