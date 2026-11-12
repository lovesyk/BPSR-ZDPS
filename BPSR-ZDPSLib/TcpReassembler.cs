using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net;
using PacketDotNet;
using Serilog;
using SharpPcap;

namespace BPSR_ZDPSLib;

public class TcpReassembler
{
    public static ILogger Log = Serilog.Log.ForContext<TcpReassembler>();

    public static TimeSpan ConnectionCleanUpInterval = TimeSpan.FromSeconds(60);
    public Action<TcpConnection> OnNewConnection;
    public Action<TcpConnection>? OnConnectionStalled;
    public Action<TcpConnection>? OnConnectionSynced;
    public ConcurrentDictionary<IPEndPoint, TcpConnection> Connections = new();
    public DateTime LastConnectionCleanUpTime = DateTime.MinValue;
    /// <summary>
    /// The capture clock: the arrival time of the most recent packet. All stall / timeout logic runs on this instead of the
    /// wall clock so that replaying a capture file behaves the same as capturing it live (and is independent of the replay speed).
    /// </summary>
    public DateTime Clock { get; private set; } = DateTime.MinValue;
    private long NextConnectionId = 0;

    public void AddPacket(IPv4Packet ipPacket, TcpPacket tcpPacket, PosixTimeval timeval)
    {
        try
        {
            Clock = timeval.Date;
            var ep = new IPEndPoint(ipPacket.SourceAddress, tcpPacket.SourcePort);
            if (!Connections.ContainsKey(ep))
            {
                var destEp = new IPEndPoint(ipPacket.DestinationAddress, tcpPacket.DestinationPort);
                var newConn = new TcpConnection(ep, destEp, this) { Id = Interlocked.Increment(ref NextConnectionId) };
                Connections.TryAdd(ep, newConn);
                OnNewConnection?.Invoke(newConn);
                Log.Information("Got a new connection {ep}", ep);
            }

            var conn = Connections[ep];
            if (tcpPacket.Reset || tcpPacket.Finished || tcpPacket.Synchronize)
            {
                RemoveConnection(conn);
                Log.Information($"Removed connection {ep}, Reset: {tcpPacket.Reset}, Finished: {tcpPacket.Finished}, Synchronize: {tcpPacket.Synchronize}");
                return;
            }

            conn.AddPacket(tcpPacket, timeval);
            RemoveTimedOutConnections();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error adding packet.");
        }
    }

    public void RemoveConnection(ConnectionId connId)
    {
        if (Connections.TryGetValue(connId.SrcEp, out var srcConn))
        {
            RemoveConnection(srcConn);
        }

        if (Connections.TryGetValue(connId.DestEp, out var destConn))
        {
            RemoveConnection(destConn);       
        }
    }

    private void RemoveTimedOutConnections()
    {
        if (LastConnectionCleanUpTime == DateTime.MinValue)
            LastConnectionCleanUpTime = Clock;

        if (Clock - LastConnectionCleanUpTime >= ConnectionCleanUpInterval)
        {
            var toRemove = new List<TcpConnection>();
            foreach (var connection in Connections)
            {
                if ((Clock - connection.Value.LastPacketAt).TotalSeconds >= 60)
                {
                    toRemove.Add(connection.Value);
                }
            }

            foreach (var connection in toRemove)
            {
                RemoveConnection(connection);
            }

            LastConnectionCleanUpTime = Clock;
            if (toRemove.Count > 0)
            {
                Log.Information($"Removed {toRemove.Count} connections");
            }
        }
    }

    /// <summary>
    /// Removes the connection so a new one is created for the next packet of this endpoint.
    /// Unless <paramref name="discardPending"/> is set the reader still gets to consume the data already buffered
    /// (a FIN / RST normally directly follows the last bytes of the stream, which must not be lost).
    /// </summary>
    public void RemoveConnection(TcpConnection conn, bool discardPending = false)
    {
        conn.IsAlive = false;
        // Only remove the entry if it is still this instance, a newer connection may already have replaced it
        Connections.TryRemove(new KeyValuePair<IPEndPoint, TcpConnection>(conn.EndPoint, conn));
        if (discardPending)
        {
            conn.CancelTokenSrc.Cancel();
            conn.Pipe.Reader.CancelPendingRead();
        }
        conn.CompleteWriter();
    }

    /// <summary>Ends all streams after the last packet was fed (offline replay), letting readers drain what is buffered.</summary>
    public void CompleteAll()
    {
        foreach (var conn in Connections.Values.ToList())
        {
            RemoveConnection(conn);
        }
    }

    public class TcpConnection(IPEndPoint endPoint, IPEndPoint destEndPoint, TcpReassembler owner)
    {
        public const int NUM_PACKETS_BEFORE_CLEAN_UP = 200;
        public const int MAX_DUPE_PACKET_SEQ_DIFF = 1700;
        // How long buffered packets may wait on a missing segment before the stream is considered lost
        public static readonly TimeSpan GAP_STALL_TIMEOUT = TimeSpan.FromSeconds(5);

        public IPEndPoint EndPoint = endPoint;
        public IPEndPoint DestEndPoint = destEndPoint;
        public SortedDictionary<uint, PacketFragment> Packets = new();
        public uint? NextExpectedSeq = null;
        public uint LastSeq = 0;
        // No writer back pressure: segments are written without awaiting the flush, and a slow reader must not stall the capture thread
        public Pipe Pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 0));
        private readonly object WriterLock = new();
        private bool WriterCompleted;
        public long Id;
        /// <summary>Arrival time per pushed segment, keyed by the cumulative stream offset at the end of the segment.</summary>
        public ConcurrentQueue<(ulong EndOffset, DateTime Time)> SegmentTimes = new();
        public bool IsAlive = true;
        public DateTime LastPacketAt = DateTime.MinValue;
        public ulong NumBytesSent;
        public ulong NumPacketsSeen;
        public CancellationTokenSource CancelTokenSrc = new();
        public bool IsSynced = false;
        public TcpReassembler Owner = owner;
        public DateTime LastPacketTime;
        public DateTime LastProgressAt = DateTime.MinValue;

        static bool SeqLt(uint a, uint b) => unchecked((int)(a - b)) < 0;
        static bool SeqGt(uint a, uint b) => unchecked((int)(a - b)) > 0;
        static bool SeqLe(uint a, uint b) => unchecked((int)(a - b)) <= 0;

        public void AddPacket(TcpPacket tcpPacket, PosixTimeval timeVal)
        {
            if (tcpPacket.Synchronize)
            {
                NextExpectedSeq = tcpPacket.SequenceNumber + 1;
                Log.Information("Got a Sync Tcp Packet.");
                Console.WriteLine("Got a Sync Tcp Packet.");
                return;
            }

            var payload = tcpPacket.PayloadData.ToArray();
            if (payload.Length <= 0)
            {
                return;
            }

            if (!IsSynced)
            {
                if (payload.Length >= 6 && BinaryPrimitives.ReadInt32BigEndian(payload) == payload.Length &&
                    (BinaryPrimitives.ReadInt16BigEndian(payload.AsSpan()[4..]) & 0x7FFF) <= 9)
                {
                    IsSynced = true;
                    LastProgressAt = Owner.Clock;
                    Log.Information($"Connection {EndPoint} is synced");
                    Owner.OnConnectionSynced?.Invoke(this);
                }
                else {
                    return;
                }
            }

            if (Packets.ContainsKey(tcpPacket.SequenceNumber))
            {
                Log.Warning("{SrcEp} -> {DestEp} has duplicate packet {SequenceNumber}, LastSeq: {LastSeq}, Packets.Len: {numPackets}",
                    EndPoint, DestEndPoint, tcpPacket.SequenceNumber, LastSeq, Packets.Count);

                // I don't like this but its a catch for something going wrong
                if (unchecked(tcpPacket.SequenceNumber - LastSeq) >= MAX_DUPE_PACKET_SEQ_DIFF)
                {
                    Log.Error("{SrcEp} -> {DestEp} dupe exceeded {MAX_DUPE_PACKET_SEQ_DIFF}, removing stream to reset :<, SequenceNumber: {SequenceNumber}, LastSeq: {LastSeq}, Diff {Diff}",
                        EndPoint, DestEndPoint, MAX_DUPE_PACKET_SEQ_DIFF, tcpPacket.SequenceNumber, LastSeq, (tcpPacket.SequenceNumber - LastSeq));
                    
                    Owner.RemoveConnection(this);
                    return;
                }
            }

            if (tcpPacket.SequenceNumber < LastSeq)
            {
                Log.Warning("{SrcEp} -> {DestEp} tcpPacket.SequenceNumber < LastSeq, {SequenceNumber} < {LastSeq}",
                    EndPoint, DestEndPoint, tcpPacket.SequenceNumber, LastSeq);
            }

            if (SeqLt(tcpPacket.SequenceNumber, NextExpectedSeq ?? 0) &&
                (tcpPacket.SequenceNumber + payload.Length) > NextExpectedSeq)
            {
                Log.Warning("{SrcEp} -> {DestEp} had overlap! NextExpectedSeq: {NextExpectedSeq}, SeqNumber: {SequenceNumber} to {PacketEndPos}",
                    EndPoint, DestEndPoint, NextExpectedSeq, tcpPacket.SequenceNumber, (tcpPacket.SequenceNumber + payload.Length));
            }
            
            if (NextExpectedSeq == null)
                NextExpectedSeq = tcpPacket.SequenceNumber;

            var fragment = new PacketFragment(tcpPacket.SequenceNumber, payload, timeVal.Date);
            Packets.TryAdd(tcpPacket.SequenceNumber, fragment);
            NumPacketsSeen++;
            LastPacketAt = Owner.Clock;
            if (LastProgressAt == DateTime.MinValue)
                LastProgressAt = Owner.Clock;
            CheckAndPushContinuesData();
        }

        private void CheckAndPushContinuesData()
        {
            bool consumedSomething = false;

            do
            {
                consumedSomething = false;

                var packetsToRemove = new List<uint>();

                if (Packets.TryGetValue(NextExpectedSeq.Value, out var exactFrag))
                {
                    Packets.Remove(NextExpectedSeq.Value);
                    PushPacketSegment(exactFrag);
                    consumedSomething = true;
                    continue;
                }

                foreach (var packet in Packets)
                {
                    if (SeqLt(packet.Value.SequenceNumber, NextExpectedSeq.Value) &&
                        SeqGt(packet.Value.SequenceNumber + (uint)packet.Value.PayloadData.Length, NextExpectedSeq.Value))
                    {
                        uint skip = NextExpectedSeq.Value - packet.Value.SequenceNumber;

                        var data = packet.Value.PayloadData.AsSpan((int)skip);
                        Push(data, packet.Value.ArriveTime);

                        NextExpectedSeq = unchecked(packet.Value.SequenceNumber + (uint)packet.Value.PayloadData.Length);
                        LastSeq = unchecked(packet.Value.SequenceNumber + (uint)data.Length);

                        packetsToRemove.Add(packet.Value.SequenceNumber);

                        consumedSomething = true;

                        Log.Information("Had overlapping packet");
                        Console.WriteLine("Had overlapping packet");

                        break;
                    }
                }

                foreach (var packet in packetsToRemove)
                {
                    Packets.Remove(packet);
                }
            } while (consumedSomething);

                
            /*while (NextExpectedSeq.HasValue && Packets.TryGetValue(NextExpectedSeq.Value, out var segment))
            {
                Packets.Remove(NextExpectedSeq.Value);
                PushPacketSegment(segment);
            }*/

            if (Packets.Count == 0)
            {
                LastProgressAt = Owner.Clock;
            }
            else if (Owner.Clock - LastProgressAt >= GAP_STALL_TIMEOUT)
            {
                // A segment went missing (e.g. the capture link dropped) and never arrived, so the stream can't continue.
                // Drop the connection so it is re-created and re-synced on the next packet.
                Log.Warning("{SrcEp} -> {DestEp} stalled on missing seq {Seq} with {Count} packets buffered, removing stream to resync",
                    EndPoint, DestEndPoint, NextExpectedSeq, Packets.Count);
                Owner.RemoveConnection(this);
                Owner.OnConnectionStalled?.Invoke(this);
                return;
            }

            if (Packets.Count >= NUM_PACKETS_BEFORE_CLEAN_UP)
            {
                RemoveOldCachedPackets();
            }
        }

        private void Push(ReadOnlySpan<byte> data, DateTime arrivalTime)
        {
            // The writer is used by the capture thread, but completed from other threads too (reader resync, Stop)
            lock (WriterLock)
            {
                if (WriterCompleted)
                    return;

                LastPacketTime = arrivalTime;
                var mem = Pipe.Writer.GetMemory(data.Length);
                data.CopyTo(mem.Span);
                Pipe.Writer.Advance(data.Length);
                Pipe.Writer.FlushAsync();
                NumBytesSent += (ulong)data.Length;
                SegmentTimes.Enqueue((NumBytesSent, arrivalTime));
            }
        }

        public void CompleteWriter()
        {
            lock (WriterLock)
            {
                if (WriterCompleted)
                    return;

                WriterCompleted = true;
                Pipe.Writer.Complete();
            }
        }

        private void PushPacketSegment(PacketFragment segment)
        {
            Push(segment.PayloadData, segment.ArriveTime);

            NextExpectedSeq = segment.SequenceNumber + (uint)segment.PayloadData.Length;
            LastSeq = segment.SequenceNumber;
            LastProgressAt = Owner.Clock;
        }

        public void RemoveOldCachedPackets()
        {
            var toRemove = Packets.Where(x => x.Value.SequenceNumber < LastSeq ||
                                x.Value.PayloadData.Length == 0 ||
                                (Owner.Clock - x.Value.ArriveTime).TotalSeconds >= 20).ToList();

            if (toRemove.Count() > 0)
                Log.Information($"{EndPoint} -> {DestEndPoint}, Cleaned up {toRemove.Count()} packets");

            foreach (var item in toRemove)
            {
                Packets.Remove(item.Key);
            }
        }
    }
}

public class PacketFragment(uint seqNum, byte[] data, DateTime arrivalTime)
{
    public uint SequenceNumber = seqNum;
    public byte[] PayloadData = data;
    public DateTime ArriveTime = arrivalTime;
}