using System.Buffers.Binary;
using PacketDotNet;
using Serilog;
using SharpPcap;

namespace BPSR_ZDPSLib;

/// <summary>
/// Minimal classic libpcap file writer (microsecond resolution), so recording does not depend on libpcap's savefile API.
/// </summary>
public sealed class PcapFileWriter : IDisposable
{
    private readonly FileStream _stream;
    private readonly object _lock = new();
    private bool _disposed;

    public long PacketCount { get; private set; }

    public PcapFileWriter(string path, LinkLayers linkType, uint snapLength = 262144)
    {
        _stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024);
        Span<byte> header = stackalloc byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], 4);
        BinaryPrimitives.WriteInt32LittleEndian(header[8..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], snapLength);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], (uint)(int)linkType);
        _stream.Write(header);
    }

    /// <param name="originalLength">Length of the packet on the wire, larger than <paramref name="data"/> when the capture truncated it.</param>
    public void Write(PosixTimeval time, ReadOnlySpan<byte> data, int originalLength)
    {
        Span<byte> header = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)time.Seconds);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], (uint)time.MicroSeconds);
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..], (uint)Math.Max(originalLength, data.Length));
        lock (_lock)
        {
            if (_disposed)
                return;
            _stream.Write(header);
            _stream.Write(data);
            PacketCount++;
        }
    }

    public void Flush()
    {
        lock (_lock)
        {
            if (!_disposed)
                _stream.Flush();
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
                return;
            _disposed = true;
            _stream.Dispose();
        }
    }
}

public readonly record struct ReplayStats(long PacketCount, DateTime? FirstPacketTime, DateTime? LastPacketTime);

/// <summary>
/// Minimal reader for classic pcap files (either endianness, micro- or nanosecond timestamps). pcapng is not supported.
/// </summary>
public sealed class PcapFileReader : IDisposable
{
    private readonly FileStream _stream;
    private readonly bool _bigEndian;
    private readonly bool _nanos;

    public LinkLayers LinkType { get; }

    public PcapFileReader(string path)
    {
        _stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024);
        Span<byte> header = stackalloc byte[24];
        if (_stream.Read(header) != 24)
            throw new InvalidDataException($"{path} is too short to be a pcap file");

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        switch (magic)
        {
            case 0xA1B2C3D4: break;
            case 0xA1B23C4D: _nanos = true; break;
            case 0xD4C3B2A1: _bigEndian = true; break;
            case 0x4D3CB2A1: _bigEndian = true; _nanos = true; break;
            case 0x0A0D0D0A: throw new InvalidDataException($"{path} is a pcapng file, only classic pcap is supported (capture with tcpdump -w / use the recorder)");
            default: throw new InvalidDataException($"{path} is not a pcap file (magic 0x{magic:X8})");
        }

        LinkType = (LinkLayers)(int)ReadU32(header[20..]);
    }

    private uint ReadU32(ReadOnlySpan<byte> s) => _bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s);

    /// <summary>Reads all packets; a truncated trailing record (e.g. the recorder was killed mid-write) ends the sequence quietly.</summary>
    public IEnumerable<RawCapture> ReadPackets()
    {
        var header = new byte[16];
        while (true)
        {
            if (!ReadFully(header, 16))
                yield break;

            var seconds = ReadU32(header);
            var fraction = ReadU32(header.AsSpan(4));
            var capLen = ReadU32(header.AsSpan(8));
            var origLen = ReadU32(header.AsSpan(12));
            if (capLen > 64 * 1024 * 1024)
            {
                Log.Warning("Pcap record at offset {Offset} claims {Length} bytes, the file is corrupt from here on; stopping", _stream.Position - 16, capLen);
                yield break;
            }

            var data = new byte[capLen];
            if (!ReadFully(data, (int)capLen))
                yield break;

            yield return new RawCapture(LinkType, new PosixTimeval(seconds, _nanos ? fraction / 1000 : fraction), data, (int)origLen);
        }
    }

    private bool ReadFully(byte[] buffer, int count)
    {
        var read = 0;
        while (read < count)
        {
            var n = _stream.Read(buffer, read, count - read);
            if (n <= 0)
                return false;
            read += n;
        }
        return true;
    }

    public void Dispose() => _stream.Dispose();
}
