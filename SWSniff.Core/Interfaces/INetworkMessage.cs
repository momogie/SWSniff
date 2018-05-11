namespace SWSniff.Core.Interfaces
{
    public interface INetworkMessage
    {
        int SocketId { get; }
        
        byte[] Data { get; }
        
        bool HasData { get; }
    }
}