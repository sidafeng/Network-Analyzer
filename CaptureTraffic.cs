using SharpPcap;
using System;
using System.Collections.Generic;
using System.Text;
using SharpPcap.LibPcap;

namespace Network_Analyzer
{
    class CaptureTraffic
    {
        private LibPcapLiveDevice? device;

        public void StartCapture()
        {
            device = LibPcapLiveDeviceList.Instance[0];

            device.OnPacketArrival += Device_OnPacketArrival;
            device.Open();
            device.StartCapture();
        }

        public void StopCapture()
        {
            if (device != null)
            {
                device.StopCapture();
                device.Close();
            }
        }

        private void Device_OnPacketArrival(
            object sender,
            PacketCapture e)
        {
            RawCapture rawPacket = e.GetPacket();

            Console.WriteLine(rawPacket);
        }
    }
}
