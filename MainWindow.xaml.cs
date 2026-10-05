using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

//using PcapViewer;

namespace Network_Analyzer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ObservableCollection<CapturedPacket> packets = new ObservableCollection<CapturedPacket>();
        public MainWindow()
        {
            InitializeComponent();
            PacketGrid.ItemsSource = packets;
            LoadCaptureDevices();
        }
        private string? currentFilePath;
        private LibPcapLiveDevice? selectNIC; //Sharpcap class
        private int packetNumber = 0;
        private bool isCapturing = false;


        private async void MenuItem_FileOpen_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFile = new OpenFileDialog();
            openFile.Title = "Open Packet Capture";
            openFile.Filter = "Packet capture|*.pcap;*.pcapng;*cap|All files|*.*";

            //updates title text after file is opened
            if (openFile.ShowDialog() == true)
            {
                packets.Clear();
                Title = $"Pcap Viewer - {System.IO.Path.GetFileName(openFile.FileName)}";
                currentFilePath = openFile.FileName;
                try
                {
                   await Task.Run(() => LoadFile(currentFilePath));
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Cannot open file!");
                }

            }

        }

        private void LoadFile(string fileName)
        {
            int indexNumber = 0;

            CaptureFileReaderDevice device = new CaptureFileReaderDevice(fileName); //from SharpPcap, reads files
            
            device.OnPacketArrival += (object sender, PacketCapture e) =>
            {
                RawCapture rawPacket = e.GetPacket(); //saves the packet for export/saving later
                
                CapturedPacket row = PacketParser.ParsePacket(++indexNumber, rawPacket);
                Dispatcher.Invoke(() => packets.Add(row));
            };

            try
            {
                device.Open();
                device.Capture();
            }
            catch (Exception ex) 
            {
                MessageBox.Show("File open failed!");
            }
            finally
            {
                device.Close();
            }
        }

        private void PacketGrid_Select(object sender, SelectionChangedEventArgs e)
        {
            CapturedPacket? selectedPacket = PacketGrid.SelectedItem as CapturedPacket;

            if (selectedPacket == null)
            {
                return;
            } 
            PacketDetails(selectedPacket);
        }

        private void PacketDetails(CapturedPacket packet)//display for detail section
        {
            PacketDetailsTree.Items.Clear();

            byte[] data = packet.RawData;

            TreeViewItem frame = new TreeViewItem
            {
                Header = $"frame {packet.Number}",
                IsExpanded = true
            };


            frame.Items.Add($"Captured time {packet.Timestamp.ToString()}");
            frame.Items.Add($"Packet size {packet.Length} bytes");

            PacketDetailsTree.Items.Add(frame);

            // check for proper header length
            if (data.Length < 14)
            {
                AddMessage("Invalid Packet Header");
                return;
            }

            TreeViewItem ethernet = new TreeViewItem
            {
                Header = "Ethernet",
                IsExpanded = true
            };

            //parse MAC address
            string destMac = "";
            string srcMac = "";
            for (int i = 0; i < 5; i++)
            {
                destMac += $"{data[i]:X2}" + ":";
                srcMac += $"{data[i + 5]:X2}" + ":";
            }
            destMac += $"{data[5]:X2}";
            srcMac += $"{data[10]:X2}" + ":";

            ethernet.Items.Add($"Destination MAC: {destMac}");
            ethernet.Items.Add($"Source MAC: {srcMac}");

            int etherType = (int)((data[12] << 8) | data[13]);
            ethernet.Items.Add($"Type: 0x{etherType:X4}");

            PacketDetailsTree.Items.Add(ethernet);

            // 0x0800 means the Ethernet payload is IPv4.
            if (etherType != 0x0800)//////////////////////////////////
            {
                AddMessage("This is not an IPv4 Ethernet packet yet.");
                return;
            }

            int ipOffset = 14;

            if (data.Length < ipOffset + 20)
            {
                AddMessage("Packet is too short to contain an IPv4 header.");
                return;
            }

            int version = data[ipOffset] >> 4;
            int ipHeaderLength = (data[ipOffset] & 0x0F) * 4;
            int ttl = data[ipOffset + 8];
            int protocolNumber = data[ipOffset + 9];

            string sourceIp = ReadIPv4Address(data, ipOffset + 12);
            string destinationIp = ReadIPv4Address(data, ipOffset + 16);

            TreeViewItem ipv4 = new TreeViewItem
            {
                Header = "Internet Protocol Version 4",
                IsExpanded = true
            };

            AddField(ipv4, "Version", version.ToString());
            AddField(ipv4, "Header length", $"{ipHeaderLength} bytes");
            AddField(ipv4, "Time to live", ttl.ToString());
            AddField(ipv4, "Protocol", GetProtocolName(protocolNumber));
            AddField(ipv4, "Source address", sourceIp);
            AddField(ipv4, "Destination address", destinationIp);

            PacketDetailsTree.Items.Add(ipv4);

            int transportOffset = ipOffset + ipHeaderLength;

            if (protocolNumber == 6)
            {
                ShowTcpDetails(data, transportOffset);
            }
            else if (protocolNumber == 17)
            {
                ShowUdpDetails(data, transportOffset);
            }
        }

        private void ShowTcpDetails(byte[] data, int tcpOffset)
        {
            if (data.Length < tcpOffset + 20)
            {
                AddMessage("Packet is too short to contain a TCP header.");
                return;
            }

            ushort sourcePort = ReadUInt16BigEndian(data, tcpOffset);
            ushort destinationPort = ReadUInt16BigEndian(data, tcpOffset + 2);
            uint sequenceNumber = ReadUInt32BigEndian(data, tcpOffset + 4);
            uint acknowledgmentNumber = ReadUInt32BigEndian(data, tcpOffset + 8);

            int tcpHeaderLength = (data[tcpOffset + 12] >> 4) * 4;
            byte flags = data[tcpOffset + 13];

            TreeViewItem tcp = new TreeViewItem
            {
                Header = "Transmission Control Protocol",
                IsExpanded = true
            };

            AddField(tcp, "Source port", sourcePort.ToString());
            AddField(tcp, "Destination port", destinationPort.ToString());
            AddField(tcp, "Sequence number", sequenceNumber.ToString());
            AddField(tcp, "Acknowledgment number", acknowledgmentNumber.ToString());
            AddField(tcp, "Header length", $"{tcpHeaderLength} bytes");
            AddField(tcp, "Flags", $"0x{flags:X2}");

            PacketDetailsTree.Items.Add(tcp);
        }

        private void ShowUdpDetails(byte[] data, int udpOffset)
        {
            if (data.Length < udpOffset + 8)
            {
                AddMessage("Packet is too short to contain a UDP header.");
                return;
            }

            ushort sourcePort = ReadUInt16BigEndian(data, udpOffset);
            ushort destinationPort = ReadUInt16BigEndian(data, udpOffset + 2);
            ushort udpLength = ReadUInt16BigEndian(data, udpOffset + 4);

            TreeViewItem udp = new TreeViewItem
            {
                Header = "User Datagram Protocol",
                IsExpanded = true
            };

            AddField(udp, "Source port", sourcePort.ToString());
            AddField(udp, "Destination port", destinationPort.ToString());
            AddField(udp, "Length", $"{udpLength} bytes");

            PacketDetailsTree.Items.Add(udp);
        }

        private void AddField(TreeViewItem parent, string name, string value)
        {
            parent.Items.Add(new TreeViewItem{Header = $"{name}: {value}" });
        }

        private void AddMessage(string message)
        {
            PacketDetailsTree.Items.Add(new TreeViewItem
            {
                Header = message
            });
        }

        private ushort ReadUInt16BigEndian(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private uint ReadUInt32BigEndian(byte[] data, int offset)
        {
            return (uint)(
                (data[offset] << 24) |
                (data[offset + 1] << 16) |
                (data[offset + 2] << 8) |
                data[offset + 3]);
        }

        private string ReadIPv4Address(byte[] data, int offset)
        {
            return $"{data[offset]}.{data[offset + 1]}." +
                   $"{data[offset + 2]}.{data[offset + 3]}";
        }

        private string GetProtocolName(int protocolNumber)
        {
            return protocolNumber switch
            {
                1 => "ICMP (1)",
                6 => "TCP (6)",
                17 => "UDP (17)",
                _ => $"Unknown ({protocolNumber})"
            };
        }

        private void LiveDevice_OnPacketArrival(object sender, PacketCapture e)
        {
            RawCapture rawPacket = e.GetPacket();
            CapturedPacket row = PacketParser.ParsePacket(++packetNumber, rawPacket);
            Dispatcher.Invoke(() => packets.Add(row));
        }

        private void btnCapture_Clicked(object sender, RoutedEventArgs e)
        {
            ComboBoxItem selectedItem = (ComboBoxItem)CaptureDeviceComboBox.SelectedItem;


            LibPcapLiveDevice selectedDevice = (LibPcapLiveDevice)selectedItem.Tag;


            selectNIC = selectedDevice;

            packets.Clear();
            packetNumber = 0;

            PacketDetailsTree.Items.Clear();
            HexViewer.Clear();

            selectNIC.OnPacketArrival += LiveDevice_OnPacketArrival;
            selectNIC.Open();
            selectNIC.StartCapture();

            isCapturing = true;

            btnCapture.Content = "CAPTURING";
            btnCapture.Foreground = Brushes.Red;
        }



        private void btnCapture_Unclicked(object sender, RoutedEventArgs e)
        {
            if (selectNIC != null)
            {
                selectNIC.StopCapture();
                selectNIC.OnPacketArrival -= LiveDevice_OnPacketArrival;
                selectNIC.Close();

                selectNIC = null;
            }
            isCapturing = false;
            btnCapture.Content = "CAPTURE";
            btnCapture.Foreground = Brushes.LimeGreen; 

        }

        private void LoadCaptureDevices()
        {
            CaptureDeviceComboBox.Items.Clear();

            try
            {
                foreach (LibPcapLiveDevice device in LibPcapLiveDeviceList.Instance)
                {

                    ComboBoxItem item = new ComboBoxItem
                    {
                        Content = device.Description,
                        Tag = device
                    };

                    CaptureDeviceComboBox.Items.Add(item);
                }

                if (CaptureDeviceComboBox.Items.Count > 0)
                {
                    CaptureDeviceComboBox.SelectedIndex = 0;
                } 

            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    ex.Message,
                    "Unable to list network devices");
            }
        }
        //save files
        private void MenuItem_FileSaveAs_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFile = new SaveFileDialog
            {
                Title = "Save Packet Capture",
                Filter = "Packet capture files|*.pcap",
                DefaultExt = ".pcap"
            };

            if (saveFile.ShowDialog() == true)
            {
                currentFilePath = saveFile.FileName;
                SavePackets(currentFilePath);

                Title = $"Pcap Viewer - {System.IO.Path.GetFileName(currentFilePath)}";
            }
        }

        private void MenuItem_FileSave_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(currentFilePath))
            {
                MenuItem_FileSaveAs_Click(sender, e);
                return;
            }

            SavePackets(currentFilePath);
        }

        private void SavePackets(string fileName)
        {
            RawCapture? firstPacket = null;

            foreach (CapturedPacket packet in packets)
            {
                if (packet.OriginalPacket != null)
                {
                    firstPacket = packet.OriginalPacket;
                    break;
                }
            }

            if (firstPacket == null)
            {
                MessageBox.Show("There are no packets to save.");
                return;
            }

            CaptureFileWriterDevice writer =
                new CaptureFileWriterDevice(fileName, FileMode.Create);

            try
            {
                writer.Open(new DeviceConfiguration
                {
                    LinkLayerType = firstPacket.LinkLayerType
                });

                foreach (CapturedPacket packet in packets)
                {
                    if (packet.OriginalPacket != null)
                    {
                        writer.Write(packet.OriginalPacket);
                    }
                }
            }
            finally
            {
                writer.Close();
            }
        }


        private void DarkMode_Checked(object sender, RoutedEventArgs e)
        {
            Background = Brushes.Black;
        }

        private void DarkMode_Unchecked(object sender, RoutedEventArgs e)
        {
            Background = Brushes.White;
        }


    }
    
}