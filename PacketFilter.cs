using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Windows.Data;
using System.Windows.Input;
using static System.Net.Mime.MediaTypeNames;

namespace Network_Analyzer
{
    internal static class PacketFilter
    {
        //private ICollectionView packetView;

        private static string[]  KeyWords = 
            {
            "ip.addr",
            "ip.src",
            "ip.dest",
            "port",
            "port.src",
            "port.dest",
            "protocol"
            };

        public static List<string> GetSuggestions(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return new List<string>();
            }
            List<string> list = new List<string>();
            foreach (var i in KeyWords)
            {
                if(i.StartsWith(text)) 
                {
                    list.Add(i);
                }
            }
            return list;
        }



        public static bool isMatch (CapturedPacket packet, string filter)
        {

            if (filter.Contains("==")){
                string column = filter.Split("==")[0].Trim();
                string value = filter.Split("==")[1].Trim();


                switch (column.ToLower())
                {
                    case "ip.addr":
                        return packet.Source.StartsWith(value) || packet.Destination.StartsWith(value);
                    case "ip.src":
                        return packet.Source.StartsWith(value);
                    case "ip.dest":
                        return packet.Destination.StartsWith(value);
                    case "port":
                        return packet.DestinationPort.StartsWith(value) || packet.SourcePort.StartsWith(value);
                    case "port.src":
                        return packet.SourcePort.StartsWith(value);
                    case "port.dest":
                        return packet.DestinationPort.StartsWith(value);
                    case "protocol":
                        return packet.Protocol.StartsWith(value);
                    default:
                        return false;
                }
            } else
            {
                return false;
            }
        }





    }
}
