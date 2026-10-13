using SharpPcap;
using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Text;

namespace Network_Analyzer
{
    internal class CapturedPacket
    {
        public int Number { get; set; }
        public DateTime Timestamp { get; set; }
        public string? Source { get; set; }
        public string? SourcePort { get; set; }
        public string? Destination { get; set; }
        public string? DestinationPort { get; set; }
        public string? Protocol { get; set; }
        public int Length { get; set; }
        public string? Info { get; set; }

        public byte[] RawData { get; set; } = Array.Empty<byte>();

        public RawCapture? OriginalPacket { get; set; }

        public Packet? ParsedPacket { get; set; }

    }
}
