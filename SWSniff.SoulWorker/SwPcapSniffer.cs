using System;
using System.Diagnostics;
using System.Linq;
using SWSniff.Core;
using SWSniff.Core.Interfaces;
using SWSniff.SoulWorker.Packets;

namespace SWSniff.SoulWorker
{
    public class SwPcapSniffer : PcapSnifferBase
    {
        public event PacketEventDelegate PacketAction;
        public delegate void PacketEventDelegate(object sender, SnifferEventArgs e);
        
        public SwPcapSniffer() : base(Constants.ProcName)
        {
        }

        protected override void HandlePacket(INetworkMessage msg, bool outgoing)
        {
            if (!msg.HasData)
            {
                Debugger.Break();
                return;
            }
            var data = msg.Data;

            int packetStart = 0;
            while (packetStart < data.Length)
            {
                //read cleartext packet header
                var isKnownXorOffset = BitConverter.ToInt16(data, packetStart + 0) == 0x0002;
                if (!isKnownXorOffset)
                {
                    Console.WriteLine("Unknown xor offset.");
                    Console.WriteLine($"The packet was: {(outgoing ? "[OUT]" : "[IN] ")} {string.Join("-", data.Select(x => x.ToString("X2")))}");
                    Console.WriteLine("TODO: Buffer packet and wait for the next slice.");
                }
                short packetLen = BitConverter.ToInt16(data, packetStart + 2);

                if (packetLen > data.Length)
                {
                    Console.WriteLine("Packet length mismatch.");
                    return;
                }

                //extract packet and parse it
                byte[] slice = new byte[packetLen]; //TODO: C# 7 slicing
                Array.Copy(data, packetStart, slice, 0, packetLen);
                SWPacket p = SWPacket.Parse(slice);
                PacketAction?.Invoke(this, new SnifferEventArgs(p, outgoing, msg.SocketId));

                //update packet start
                packetStart += packetLen;
            }
        }
    }
}