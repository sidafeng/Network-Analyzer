using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;


namespace Network_Analyzer
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<CapturedPacket> packets = new ObservableCollection<CapturedPacket>();//sharpcap class
        private ICollectionView packetDisplay; //WPF, helps to filter datagrid
        public MainWindow()
        {
            InitializeComponent();
            packetDisplay = CollectionViewSource.GetDefaultView(packets);
            PacketGrid.ItemsSource = packetDisplay;
            DisplayNIC();
        }
        private string? currentFilePath;
        private LibPcapLiveDevice? selectNIC; //Sharpcap class
        private int packetNumber = 0;
        private bool isCapturing = false;
        TimeLine timeline = new TimeLine();


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
                if (indexNumber == 1)
                {
                    timeline.StartTime = row.Timestamp;
                }
                Dispatcher.Invoke(() => packets.Add(row));
            };

            try
            {
                device.Open();
                device.Capture();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "File open failed!");
            }
            finally
            {
                device.Close();
            }
            if (packets.Count > 0)
            {
                timeline.EndTime = packets[packets.Count - 1].Timestamp;
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

            // check for proper header length
            if (data.Length < 14)
            {
                PacketDetailsTree.Items.Add(new TreeViewItem
                {
                    Header = "Invalid Ethernet header."
                });
                return;
            }

            TreeViewItem frame = new TreeViewItem
            {
                Header = $"Frame {packet.Number}",
                IsExpanded = true
            };


            frame.Items.Add($"Captured time {packet.Timestamp.ToString()}");
            frame.Items.Add($"Packet size {packet.Length} bytes");

            PacketDetailsTree.Items.Add(frame);

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

            if (packet.OriginalPacket == null)
            {
                return;
            }
            Packet parsedPacket = Packet.ParsePacket(packet.OriginalPacket.LinkLayerType, packet.OriginalPacket.Data);



            // 0x0800 means the Ethernet payload is IPv4.
            if (etherType == 0x0800)
            {
                int ipOffset = 14;

                int version = data[ipOffset] >> 4;
                int ipHeaderLength = (data[ipOffset] & 0x0F) * 4;
                int ttl = data[ipOffset + 8];
                int protocolNumber = data[ipOffset + 9];

                string sourceIp = data[ipOffset + 12] + "." + data[ipOffset + 13] + "." + data[ipOffset + 14] + "." + data[ipOffset + 15];
                string destinationIp = data[ipOffset + 16] + "." + data[ipOffset + 17] + "." + data[ipOffset + 18] + "." + data[ipOffset + 19];

                TreeViewItem ipv4 = new TreeViewItem
                {
                    Header = "Internet Protocol Version 4",
                    IsExpanded = true
                };
                ipv4.Items.Add($"Version: {version}");
                ipv4.Items.Add($"Header length: {ipHeaderLength} bytes");
                ipv4.Items.Add($"Time to live: {ttl}");
                ipv4.Items.Add($"Protocol: {(PacketDotNet.ProtocolType)protocolNumber}");
                ipv4.Items.Add($"Source address: {sourceIp}");
                ipv4.Items.Add($"Destination address: {destinationIp}");

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
        }

        private void ShowTcpDetails(byte[] data, int tcpOffset)
        {
            int sourcePort = ((data[tcpOffset] << 8) | data[tcpOffset + 1]);
            int destinationPort = ((data[tcpOffset + 2] << 8) | data[tcpOffset + 3]);
            long sequenceNumber = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(tcpOffset + 4, 4));
            long acknowledgmentNumber = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(tcpOffset + 8, 4));

            int tcpHeaderLength = (data[tcpOffset + 12] >> 4) * 4;
            byte flags = data[tcpOffset + 13];
            int payloadOffset = tcpOffset + tcpHeaderLength;


            TreeViewItem tcp = new TreeViewItem
            {
                Header = "Transmission Control Protocol",
                IsExpanded = true
            };

            tcp.Items.Add($"Source port: {sourcePort}");
            tcp.Items.Add($"Destination port: {destinationPort}");
            tcp.Items.Add($"Sequence number: {sequenceNumber}");
            tcp.Items.Add($"Acknowledgment number: {acknowledgmentNumber}");
            tcp.Items.Add($"Header length: {tcpHeaderLength} bytes");
            tcp.Items.Add($"Flags: 0x{flags:X2}");

            if (payloadOffset < data.Length)
            {
                string payload = Encoding.ASCII.GetString(data, payloadOffset, data.Length - payloadOffset);
                tcp.Items.Add($"Payload: {payload}");
            }

            PacketDetailsTree.Items.Add(tcp);
        }

        private void ShowUdpDetails(byte[] data, int udpOffset)
        {
            int sourcePort = ((data[udpOffset] << 8) | data[udpOffset + 1]);
            int destinationPort = (data[udpOffset + 2] << 8) | data[udpOffset + 3];
            int udpLength = ((data[udpOffset + 4] << 8) | data[udpOffset + 5]);

            TreeViewItem udp = new TreeViewItem
            {
                Header = "User Datagram Protocol",
                IsExpanded = true
            };

            udp.Items.Add($"Source port: {sourcePort}");
            udp.Items.Add($"Destination port: {destinationPort}");
            udp.Items.Add($"Length: {udpLength} bytes");
            PacketDetailsTree.Items.Add(udp);
        }

        private void LiveDevice_OnPacketArrival(object sender, PacketCapture e)
        {
            RawCapture rawPacket = e.GetPacket();
            CapturedPacket row = PacketParser.ParsePacket(++packetNumber, rawPacket);
            Dispatcher.Invoke(() => packets.Add(row));
            if (packetNumber == 1)
            {
                timeline.StartTime = row.Timestamp;
            }
        }

        private void btnCapture_Clicked(object sender, RoutedEventArgs e)
        {
            ComboBoxItem selectedItem = (ComboBoxItem)CaptureDeviceComboBox.SelectedItem;


            LibPcapLiveDevice selectedDevice = (LibPcapLiveDevice)selectedItem.Tag;


            selectNIC = selectedDevice;

            packets.Clear();
            packetNumber = 0;

            PacketDetailsTree.Items.Clear();

            selectNIC.OnPacketArrival += LiveDevice_OnPacketArrival;

            try //ensures the network card can capture
            {
                selectNIC.Open();
                selectNIC.StartCapture();
            }
            catch (Exception)
            {
                MessageBox.Show("No permission given!");
                selectNIC.OnPacketArrival -= LiveDevice_OnPacketArrival;
                selectNIC.Close();
                selectNIC = null;
                return;

            }

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
            if (packets.Count > 0)
            {
                timeline.EndTime = packets[packets.Count - 1].Timestamp;
            }
        }

        private void DisplayNIC()
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
                MessageBox.Show(ex.Message, "Unable to list network devices");
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

            if (packets.Count == 0)
            {
                MessageBox.Show("There is nothing to save");
                return;
            }

            if (saveFile.ShowDialog() == true)
            {
                currentFilePath = saveFile.FileName;
                SavePackets(saveFile.FileName);

                Title = $"Pcap Viewer - {currentFilePath}";
            }
        }

        private void MenuItem_FileSave_Click(object sender, RoutedEventArgs e)
        {
            if (currentFilePath != null)
            {
                SavePackets(currentFilePath);
            }
        }

        private void SavePackets(string fileName)
        {
            //this part of the code need to capture the linked layer type from a packet.
            //the linked layer type is needed to format the file.
            RawCapture? sample = null;

            foreach (var i in packets)
            {
                if (i.OriginalPacket != null)
                {
                    sample = i.OriginalPacket;
                    break;
                }
            }

            CaptureFileWriterDevice writer = new CaptureFileWriterDevice(fileName, FileMode.Create);//Sharpcap object

            try
            {
                writer.Open(new DeviceConfiguration //sharpcap object
                {
                    LinkLayerType = sample.LinkLayerType
                });

                foreach (var i in packets)
                {
                    if (i.OriginalPacket != null)
                    {
                        writer.Write(i.OriginalPacket);
                    }
                }
            }
            finally
            {
                writer.Close();
            }
        }

        //private readonly Brush darkerGray = new SolidColorBrush(Color.FromRgb(45, 45, 45));
        //private readonly Brush moreDark = new SolidColorBrush(Color.FromRgb(30, 30, 30));

        private void ApplyTheme(string themeFile)
        {
            var dictionaries = System.Windows.Application.Current.Resources.MergedDictionaries;
            dictionaries.Clear(); // Only use this if these are your only app-level merged dictionaries.
            dictionaries.Add(new ResourceDictionary
            {
                Source = new Uri($"Theme/{themeFile}", UriKind.Relative)
            });
        }

        private void DarkMode_Checked(object sender, RoutedEventArgs e)
        {

            ApplyTheme("Dark.xaml");

            //Background = moreDark;
            //Foreground = Brushes.White;
            //PacketGrid.Background = darkerGray;
            //PacketGrid.Foreground = Brushes.White;

            //Style cellStyle = new Style(typeof(DataGridCell));

            //cellStyle.Setters.Add(new Setter(Control.BackgroundProperty, darkerGray));
            //cellStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));

            //PacketGrid.CellStyle = cellStyle;
            //PacketDetailsTree.Background = darkerGray;
            //PacketDetailsTree.Foreground = Brushes.White;


            //cliView.Background = darkerGray;
            //cliView.Foreground = Brushes.White;
            //FilterTextBox.Background = darkerGray;
            //FilterTextBox.Foreground = Brushes.White;
            //SuggestionList.Background = darkerGray;
            //SuggestionList.Foreground = Brushes.White;
            ////CaptureDeviceComboBox.Background = Brushes.DimGray;
            ////CaptureDeviceComboBox.Foreground = Brushes.White;
            //Style headerStyle = new Style(typeof(DataGridColumnHeader));
            //headerStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.DarkSlateGray));
            //headerStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));


            //PacketGrid.ColumnHeaderStyle = headerStyle;


            //MainMenu.Background = moreDark;
            //MainMenu.Foreground = Brushes.White;
            ////DropDownMenu.Background = moreDark;
            ////DropDownMenu.Foreground = Brushes.White;

        }

        private void DarkMode_Unchecked(object sender, RoutedEventArgs e)
        {

            ApplyTheme("Light.xaml");


            //MainMenu.Background = Brushes.White;
            //MainMenu.Foreground = Brushes.Black;
            //Background = Brushes.White;
            //Foreground = Brushes.Black;
            //PacketGrid.Background = Brushes.WhiteSmoke;
            //PacketGrid.Foreground = Brushes.Black;
            //Style cellStyle = new Style(typeof(DataGridCell));

            //cellStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.WhiteSmoke));
            //cellStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));

            //PacketGrid.CellStyle = cellStyle;

            //PacketDetailsTree.Background = Brushes.White;
            //PacketDetailsTree.Foreground = Brushes.Black;

            //cliView.Background = Brushes.White;
            //cliView.Foreground = Brushes.Black;
            //FilterTextBox.Background = Brushes.White;
            //FilterTextBox.Foreground = Brushes.Black;
            ////CaptureDeviceComboBox.Background = Brushes.White;
            ////CaptureDeviceComboBox.Foreground = Brushes.Black;
            //Style headerStyle = new Style(typeof(DataGridColumnHeader));
            //headerStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.WhiteSmoke));
            //headerStyle.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.Black));
            //PacketGrid.ColumnHeaderStyle = headerStyle;
        }

        private void FilterTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string filter = FilterTextBox.Text.Trim();

            SuggestionList.ItemsSource = PacketFilter.GetSuggestions(filter);

            SuggestionPopup.IsOpen = SuggestionList.Items.Count > 0;


            packetDisplay.Filter = item =>
            {
                if (filter.Contains("==") && filter.Split("==")[1] != null)
                {
                    CapturedPacket packet = (CapturedPacket)item;

                    if (filter == "")
                        return true;

                    return PacketFilter.isMatch(packet, filter);
                }
                return true;
            };

        }

        private void SuggestionList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (SuggestionList.SelectedItem is string keyword)
            {
                FilterTextBox.Text = keyword;
                FilterTextBox.CaretIndex = FilterTextBox.Text.Length;
                SuggestionPopup.IsOpen = false;
            }
        }

        private void ClearFilter_Click(object sender, RoutedEventArgs e)
        {
            FilterTextBox.Clear();
        }
        private void ViewTimeLine_Click(object sender, RoutedEventArgs e)
        {
            if (packets.Count == 0)
            {
                MessageBox.Show("nothing to display.");
                return;
            } else
            {
                TimeLineWindow window = new TimeLineWindow(timeline, packets, packets.Count);
                window.Show();
            }

        }

        private void MenuItem_Exit_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Application.Current.Shutdown(); //need this to also close timeline
        }

        private void MenuItem_About_Click(object sender, RoutedEventArgs e)
        {
            AboutWindow about = new AboutWindow();
            about.ShowDialog();
        }

        private void EnterKey(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                string rule = RuleInput.Text.Trim();

                //Add rule matching logic

                RuleList.Items.Add(rule);
                
            }
        }

        public void Clear_Grid_Click(object sender, RoutedEventArgs e)
        {
            packets.Clear();
        }



    }

}