using System.Buffers;

namespace BPSR_ZDPSLib;

public class RawPacket
{
    public byte[] Data { get; set; }
    public int Len { get; set; }
    public DateTime LastPacketTime { get; set; } = DateTime.MinValue;
    public System.Net.IPEndPoint? Source { get; set; }
    public System.Net.IPEndPoint? Destination { get; set; }
    public long StreamId { get; set; }
    public long StreamIndex { get; set; }
    public long StreamOffset { get; set; }

    public void Set(int len)
    {
        Data = ArrayPool<byte>.Shared.Rent(len);
        Len = len;
    }
    
    public void Return()
    {
        ArrayPool<byte>.Shared.Return(Data);
    }
}