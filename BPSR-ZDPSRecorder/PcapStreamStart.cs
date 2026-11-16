using System.Buffers.Binary;
using System.Net;
using BPSR_ZDPSLib;
using Serilog;
using SharpPcap;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// Copies a pcap so that replaying it keeps the first message of every connection whose SYN was captured.
/// ZDPSLib only starts reading a stream at a TCP segment holding exactly one message, so a first message that spans segments
/// (or shares one with the next message) is lost. The replay offers no hook to start the stream elsewhere, so the copy re-cuts
/// the start instead: the segments carrying the first message are replaced by one segment holding exactly that message, plus
/// one with the remaining bytes of those segments. The stream bytes are unchanged, only how they are split into segments.
/// </summary>
public static class PcapStreamStart
{
    // Must match what the lib accepts as a message header: the sync check and the reader's validation
    private const uint MaxMessageLength = 16 * 1024 * 1024;
    private const int MaxMessageType = 8;
    // The first message has to fit in a single segment (the IP length field); larger ones are left to the lib
    private const int MaxSegmentPayload = 60000;
    // How much may be held back per stream while its first message is incomplete
    private const int MaxHeldPackets = 256;

    public readonly record struct Stats(long PacketCount, int StreamsRecut);

    private sealed class StreamHead(uint start)
    {
        public readonly uint Start = start;
        public readonly List<(RawCapture Packet, TcpFrame Frame)> Held = [];
        public readonly List<byte> Contiguous = [];
    }

    public static Stats Rewrite(string inputPath, string outputPath)
    {
        using var reader = new PcapFileReader(inputPath);
        using var writer = new PcapFileWriter(outputPath, reader.LinkType);
        var heads = new Dictionary<(IPEndPoint, IPEndPoint), StreamHead>();
        long packetCount = 0;
        var recut = 0;

        foreach (var packet in reader.ReadPackets())
        {
            packetCount++;
            if (!TcpFrame.TryParse(packet.LinkLayerType, packet.Data, out var frame) || !frame.IsReassembled)
            {
                Write(writer, packet);
                continue;
            }

            var key = (frame.Source, frame.Destination);
            if (frame.Syn)
            {
                if (heads.Remove(key, out var previous))
                    Release(writer, previous);
                heads[key] = new StreamHead(unchecked(frame.Seq + 1));
                Write(writer, packet);
                continue;
            }

            if (!heads.TryGetValue(key, out var head))
            {
                Write(writer, packet);
                continue;
            }

            if (frame.FinOrRst || frame.Truncated)
            {
                heads.Remove(key);
                Release(writer, head);
                Write(writer, packet);
                continue;
            }

            // Pure ACKs don't reach the lib's streams
            if (frame.PayloadLength == 0)
            {
                Write(writer, packet);
                continue;
            }

            head.Held.Add((packet, frame));
            Extend(head);

            switch (TryCut(head, packet, frame, out var cut))
            {
                case CutResult.Incomplete when head.Held.Count < MaxHeldPackets:
                    break;
                case CutResult.Done:
                    heads.Remove(key);
                    foreach (var segment in cut!)
                        Write(writer, segment);
                    if (cut!.Count != 1 || !ReferenceEquals(cut[0], packet))
                        recut++;
                    break;
                default:
                    // Not a game stream, or the first message can't be cut out: leave the stream as it was
                    heads.Remove(key);
                    Release(writer, head);
                    break;
            }
        }

        foreach (var head in heads.Values)
            Release(writer, head);

        return new Stats(packetCount, recut);
    }

    private enum CutResult { Incomplete, Done, Invalid }

    /// <summary>Appends the held payloads to the contiguous bytes from the stream start, in sequence order.</summary>
    private static void Extend(StreamHead head)
    {
        bool progressed;
        do
        {
            progressed = false;
            var end = unchecked(head.Start + (uint)head.Contiguous.Count);
            foreach (var (packet, frame) in head.Held)
            {
                var segmentEnd = unchecked(frame.Seq + (uint)frame.PayloadLength);
                if (SeqLe(frame.Seq, end) && SeqGt(segmentEnd, end))
                {
                    var skip = (int)unchecked(end - frame.Seq);
                    head.Contiguous.AddRange(packet.Data.AsSpan(frame.PayloadOffset + skip, frame.PayloadLength - skip));
                    progressed = true;
                    break;
                }
            }
        } while (progressed);
    }

    private static CutResult TryCut(StreamHead head, RawCapture current, TcpFrame currentFrame, out List<RawCapture>? cut)
    {
        cut = null;
        if (head.Contiguous.Count < 6)
            return CutResult.Incomplete;

        Span<byte> header = stackalloc byte[6];
        for (var i = 0; i < 6; i++)
            header[i] = head.Contiguous[i];
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        var type = BinaryPrimitives.ReadInt16BigEndian(header[4..]) & 0x7FFF;
        if (length < 6 || length > MaxMessageLength || type > MaxMessageType || length > MaxSegmentPayload)
            return CutResult.Invalid;

        if (head.Contiguous.Count < length)
            return CutResult.Incomplete;

        // Already a single segment holding exactly the first message: the lib syncs on it by itself
        if (head.Held.Count == 1 && head.Contiguous.Count == length)
        {
            cut = [current];
            return CutResult.Done;
        }

        // The cut segments take the time of the segment that completed the message, as that is when the lib would have emitted it
        var bytes = head.Contiguous.ToArray();
        cut = [Segment(current, currentFrame, head.Start, bytes.AsSpan(0, (int)length))];
        for (var offset = (int)length; offset < bytes.Length; offset += MaxSegmentPayload)
        {
            var size = Math.Min(MaxSegmentPayload, bytes.Length - offset);
            cut.Add(Segment(current, currentFrame, unchecked(head.Start + (uint)offset), bytes.AsSpan(offset, size)));
        }

        // Held segments beyond a gap are passed on unchanged for the lib to reassemble
        var end = unchecked(head.Start + (uint)bytes.Length);
        foreach (var (packet, frame) in head.Held)
        {
            if (SeqGt(unchecked(frame.Seq + (uint)frame.PayloadLength), end))
                cut.Add(new RawCapture(packet.LinkLayerType, current.Timeval, packet.Data, packet.PacketLength));
        }

        return CutResult.Done;
    }

    private static RawCapture Segment(RawCapture template, TcpFrame frame, uint seq, ReadOnlySpan<byte> payload)
    {
        var data = frame.Rebuild(template.Data, seq, payload);
        return new RawCapture(template.LinkLayerType, template.Timeval, data, data.Length);
    }

    private static void Release(PcapFileWriter writer, StreamHead head)
    {
        foreach (var (packet, _) in head.Held)
            Write(writer, packet);
    }

    private static void Write(PcapFileWriter writer, RawCapture packet) => writer.Write(packet.Timeval, packet.Data, packet.PacketLength);

    private static bool SeqGt(uint a, uint b) => unchecked((int)(a - b)) > 0;
    private static bool SeqLe(uint a, uint b) => unchecked((int)(a - b)) <= 0;
}
