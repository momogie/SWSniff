using System;
using PacketDotNet;
using SharpPcap;
using SWSniff.Core.Interop;

namespace SWSniff.Core
{
    public abstract class PcapSnifferBase : SnifferBase
    {
        private ICaptureDevice _device;
        
        public override void Start()
        {
            var devices = CaptureDeviceList.Instance;
            
            if(devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                throw new Exception("No devices were found on this machine");
            }
            
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();
            
            int i = 0;

            // Scan the list printing every entry
            foreach(var dev in devices)
            {
                Console.WriteLine("{0}) {1}",i,dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse( Console.ReadLine() );
            
            var device = devices[i];
            
            device.OnPacketArrival += DeviceOnOnPacketArrival;
            
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            
            string filter = "net 194.187.19.0/24";
            device.Filter = filter;
            
            Console.WriteLine();
            Console.WriteLine
            ("-- The following tcpdump filter will be applied: \"{0}\"", 
                filter);
            Console.WriteLine
            ("-- WinPCap Listening on {0}...",
                device.Description);
            
            device.StartCapture();

            _device = device;
        }

        private void DeviceOnOnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            
            var ip = (IpPacket)packet.Extract(typeof(IpPacket));
            if (ip == null) return;
            var appPacket = (TcpPacket) packet.Extract(typeof(TcpPacket));
            if (appPacket == null) return;
            if (!appPacket.Psh) return;
            var message = new PcapMessage(appPacket);
            var outgoing = !ip.SourceAddress.ToString().Contains("194.187.19");
            HandlePacket(message, outgoing);
        }

        protected PcapSnifferBase(string procName) : base(procName)
        {
        }

        ~PcapSnifferBase()
        {
            if (_device != null)
            {
                _device.StopCapture();
                _device.Close();
            }
        }
    }
}