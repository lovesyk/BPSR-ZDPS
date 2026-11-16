using System.Buffers.Binary;
using System.Net;
using PacketDotNet;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// The IPv4 / TCP header fields of a captured frame, parsed by hand so the frame can also be rebuilt with a different payload.
/// Only what ZDPSLib's reassembler would see is accepted: unfragmented IPv4 carrying TCP.
/// </summary>
internal readonly record struct TcpFrame(
    int IpOffset, int IpHeaderLength, int TcpHeaderLength, int PayloadLength, bool Truncated,
    IPEndPoint Source, IPEndPoint Destination, uint Seq, byte Flags)
{
    private const byte FlagFin = 0x01, FlagSyn = 0x02, FlagRst = 0x04;

    public bool Syn => (Flags & FlagSyn) != 0;
    public bool FinOrRst => (Flags & (FlagFin | FlagRst)) != 0;
    public int PayloadOffset => IpOffset + IpHeaderLength + TcpHeaderLength;

    /// <summary>ZDPSLib drops connections with a port &lt;= 1000 before reassembly.</summary>
    public bool IsReassembled => Source.Port > 1000 && Destination.Port > 1000;

    public static bool TryParse(LinkLayers linkType, byte[] data, out TcpFrame frame)
    {
        frame = default;
        var ip = FindIpOffset(linkType, data);
        if (ip < 0 || data.Length < ip + 20 || data[ip] >> 4 != 4)
            return false;

        var ihl = (data[ip] & 0x0F) * 4;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(ip + 2));
        var fragment = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(ip + 6));
        if (ihl < 20 || data[ip + 9] != 6 || (fragment & 0x3FFF) != 0 || totalLength < ihl + 20)
            return false;

        var tcp = ip + ihl;
        if (data.Length < tcp + 20)
            return false;

        var tcpHeaderLength = (data[tcp + 12] >> 4) * 4;
        if (tcpHeaderLength < 20 || ihl + tcpHeaderLength > totalLength || data.Length < tcp + tcpHeaderLength)
            return false;

        var available = Math.Min(totalLength, data.Length - ip);
        frame = new TcpFrame(
            ip, ihl, tcpHeaderLength,
            PayloadLength: available - ihl - tcpHeaderLength,
            Truncated: available < totalLength,
            Source: new IPEndPoint(new IPAddress(data.AsSpan(ip + 12, 4)), BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(tcp))),
            Destination: new IPEndPoint(new IPAddress(data.AsSpan(ip + 16, 4)), BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(tcp + 2))),
            Seq: BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(tcp + 4)),
            Flags: data[tcp + 13]);
        return true;
    }

    /// <summary>Offset of the IPv4 header behind the link layer header, or -1 when the frame does not carry IPv4.</summary>
    private static int FindIpOffset(LinkLayers linkType, byte[] data)
    {
        switch ((int)linkType)
        {
            case 1: // Ethernet, optionally VLAN tagged
                var offset = 12;
                while (data.Length >= offset + 2)
                {
                    var etherType = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset));
                    if (etherType is 0x8100 or 0x88A8)
                    {
                        offset += 4;
                        continue;
                    }
                    return etherType == 0x0800 ? offset + 2 : -1;
                }
                return -1;
            case 0 or 108: // BSD loopback, address family in host or network byte order
                return data.Length >= 4 && (data[0] == 2 || data[3] == 2) ? 4 : -1;
            case 12 or 14 or 101: // raw IP
                return 0;
            case 113: // Linux cooked v1
                return data.Length >= 16 && BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(14)) == 0x0800 ? 16 : -1;
            case 276: // Linux cooked v2
                return data.Length >= 20 && BinaryPrimitives.ReadUInt16BigEndian(data) == 0x0800 ? 20 : -1;
            default:
                return -1;
        }
    }

    /// <summary>
    /// A copy of <paramref name="template"/> (this frame's bytes) with the sequence number and payload replaced, and the IP length
    /// and both checksums updated. Everything else, including the link layer header and the ACK number, is kept.
    /// </summary>
    public byte[] Rebuild(byte[] template, uint seq, ReadOnlySpan<byte> payload)
    {
        var headers = PayloadOffset;
        var result = new byte[headers + payload.Length];
        template.AsSpan(0, headers).CopyTo(result);
        payload.CopyTo(result.AsSpan(headers));

        var ip = IpOffset;
        var tcp = ip + IpHeaderLength;
        var tcpLength = TcpHeaderLength + payload.Length;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(ip + 2), (ushort)(IpHeaderLength + tcpLength));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(ip + 10), 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(ip + 10), Checksum(result.AsSpan(ip, IpHeaderLength), 0));

        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(tcp + 4), seq);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tcp + 16), 0);
        uint pseudo = 0;
        pseudo += Sum(result.AsSpan(ip + 12, 8));
        pseudo += 6;
        pseudo += (uint)tcpLength;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(tcp + 16), Checksum(result.AsSpan(tcp, tcpLength), pseudo));
        return result;
    }

    private static uint Sum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var i = 0;
        for (; i + 1 < data.Length; i += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(data[i..]);
        if (i < data.Length)
            sum += (uint)data[i] << 8;
        return sum;
    }

    private static ushort Checksum(ReadOnlySpan<byte> data, uint initial)
    {
        ulong sum = initial + (ulong)Sum(data);
        while (sum >> 16 != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
