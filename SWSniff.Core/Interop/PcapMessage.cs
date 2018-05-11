using PacketDotNet;
using SharpPcap;
using SWSniff.Core.Interfaces;

namespace SWSniff.Core.Interop
{
    public class PcapMessage : INetworkMessage
    {
        private readonly Packet _packet;

        public PcapMessage(Packet packet)
        {
            _packet = packet;
        }

        public int SocketId { get; } = 0;
        public byte[] Data => _packet.PayloadData;
        public bool HasData => _packet?.PayloadData != null && _packet.PayloadData.Length > 0;
    }
}