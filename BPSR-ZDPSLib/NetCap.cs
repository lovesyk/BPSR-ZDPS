using System.Buffers;
using Microsoft.Extensions.ObjectPool;
using PacketDotNet;
using Serilog;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using ZstdSharp;

namespace BPSR_ZDPSLib;

public class NetCap
{
    private NetCapConfig Config;
    public ICaptureDevice CaptureDevice;
    public TcpReassembler TcpReassempler;

    private CancellationTokenSource CancelTokenSrc = new();
    public ObjectPool<RawPacket> RawPacketPool = ObjectPool.Create(new DefaultPooledObjectPolicy<RawPacket>());
    public ConcurrentQueue<RawPacket> RawPacketQueue = new();
    private Task PacketParseTask;
    // One per frame nesting level, so decompressing a message inside an already decompressed frame does not overwrite the frame being walked
    private readonly List<byte[]> DecompressionScratchBuffers = new();
    private byte[] DecompressionScratchBuffer
    {
        get
        {
            while (DecompressionScratchBuffers.Count <= ParseDepth)
                DecompressionScratchBuffers.Add(new byte[(1024 * 1024) * 5]);
            return DecompressionScratchBuffers[ParseDepth];
        }
    }
    private int ParseDepth = 0;
    private readonly ParseContext Ctx = new();
    private Decompressor _decompressor = new();
    private Dictionary<NotifyId, Action<ReadOnlySpan<byte>, ExtraPacketData>> NotifyHandlers = new();
    private Dictionary<ProxyId, Action<ReadOnlySpan<byte>, uint, ExtraPacketData>> ProxyHandlers = new();
    private Dictionary<ProxyId, Action<ReadOnlySpan<byte>, uint, ExtraPacketData>> ProxyReturnHandlers = new();
    private ConcurrentDictionary<uint, ProxyId> ProxyReturnsDictionary = new();
    private Action<NotifyId, ReadOnlySpan<byte>, ExtraPacketData>? UnhandledHandler = null;
    private Action<ProxyId, ReadOnlySpan<byte>, ExtraPacketData>? UnhandledProxyHandler = null;
    public ulong NumSeenPackets = 0;
    public DateTime LastPacketSeenAt = DateTime.MinValue;
    public int NumConnectionReaders = 0;
    public ConcurrentDictionary<ConnectionId, bool> ConnectionFilters = new();
    public ConcurrentBag<string> ImportantLogMsgs = [];
    public ulong NumGameMessagesSeen = 0;
    public DateTime LastGameMessageAt = DateTime.MinValue;
    private const uint MaxGameMessageLength = 16 * 1024 * 1024;
    public ulong NumGameMessagesDequeued = 0;
    private bool IsReplay = false;
    private const int MaxReplayQueueLength = 20000;

    /// <summary>
    /// Raised on the parser thread for every game message that was framed (and decompressed), whether or not a handler is registered for it.
    /// The payload span is only valid for the duration of the call.
    /// </summary>
    public event GameMessageHandler? MessageReceived;

    /// <summary>Raised on the capture thread for every packet delivered by the capture device (live capture only), before any filtering.</summary>
    public event Action<RawCapture>? PacketCaptured;

    /// <summary>
    /// Raised (once per NetCap instance) when capture died unexpectedly or went silent after having seen packets.
    /// </summary>
    public event Action<string>? CaptureLost;
    /// <summary>A game stream lost data and was dropped (raised on the capture thread).</summary>
    public event Action? StreamStalled;
    /// <summary>A (re)created stream found a message boundary and started delivering data (raised on the capture thread).</summary>
    public event Action? StreamSynced;
    public TimeSpan CaptureStallTimeout { get; set; } = TimeSpan.FromSeconds(30);
    private bool IsStopping = false;
    /// <summary>True if Stop() could not stop the capture thread; the process should be restarted instead of reusing libpcap.</summary>
    public bool StopFailed { get; private set; }
    private int CaptureLostRaised = 0;
    private Task? WatchdogTask;

    private bool IsDebugCaptureFileMode = false;
    private string DebugCaptureFile = "";//@"C:\Users\Xennma\Documents\BPSR_PacketCapture.pcap";
    private DateTime LastDebugCapturePacketTime = DateTime.MinValue;

    public void Init(NetCapConfig config)
    {
        Config = config;
    }

    public void Start()
    {
        if (!string.IsNullOrEmpty(DebugCaptureFile) && IsDebugCaptureFileMode)
        {
            CaptureDevice = new CaptureFileReaderDevice(DebugCaptureFile);
            CaptureDevice.Open();
        }
        else if (Config.UseRemoteCapture)
        {
            CaptureDevice = GetRemoteCaptureDevice();
            CaptureDevice.Open(new DeviceConfiguration { ReadTimeout = 500 });
        }
        else
        {
            CaptureDevice = GetCaptureDevice();
            CaptureDevice.Open(DeviceModes.Promiscuous, 100);
        }
        

        PacketParseTask = Task.Factory.StartNew(ParsePacketsLoop, CancelTokenSrc.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        TcpReassempler = new TcpReassembler();
        TcpReassempler.OnNewConnection += OnNewConnection;
        TcpReassempler.OnConnectionStalled += _ => StreamStalled?.Invoke();
        TcpReassempler.OnConnectionSynced += _ => StreamSynced?.Invoke();

        string captureFilter = "tcp and not portrange 0-1000";
        if (Config.UseRemoteCapture && !string.IsNullOrWhiteSpace(Config.RemoteCaptureFilter))
            captureFilter += $" and {Config.RemoteCaptureFilter}";
        CaptureDevice.Filter = captureFilter;
        CaptureDevice.OnPacketArrival += DeviceOnOnPacketArrival;
        CaptureDevice.OnCaptureStopped += DeviceOnCaptureStopped;
        CaptureDevice.StartCapture();

        if (!IsDebugCaptureFileMode)
        {
            WatchdogTask = Task.Factory.StartNew(WatchdogLoop, CancelTokenSrc.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        Log.Information("Capture device started");
    }

    private void DeviceOnCaptureStopped(object sender, CaptureStoppedEventStatus status)
    {
        if (IsStopping || IsDebugCaptureFileMode)
            return;

        RaiseCaptureLost($"Capture stopped unexpectedly ({status})");
    }

    private void WatchdogLoop()
    {
        while (!CancelTokenSrc.IsCancellationRequested)
        {
            try
            {
                Task.Delay(1000, CancelTokenSrc.Token).Wait();
            }
            catch (Exception)
            {
                return;
            }

            // Only treat silence as a loss once traffic has been seen, so a game that was never started doesn't cause restarts
            if (LastPacketSeenAt != DateTime.MinValue && DateTime.Now - LastPacketSeenAt > CaptureStallTimeout)
            {
                RaiseCaptureLost($"No packets seen for over {CaptureStallTimeout.TotalSeconds:0}s");
                return;
            }

            // Packets still arrive but no game message has been parsed: the stream is stuck in a state that never recovers on its own
            if (LastGameMessageAt != DateTime.MinValue && DateTime.Now - LastGameMessageAt > CaptureStallTimeout &&
                DateTime.Now - LastPacketSeenAt < TimeSpan.FromSeconds(5))
            {
                RaiseCaptureLost($"Packets seen but no game messages parsed for over {CaptureStallTimeout.TotalSeconds:0}s");
                return;
            }
        }
    }

    private void RaiseCaptureLost(string reason)
    {
        if (IsStopping || Interlocked.Exchange(ref CaptureLostRaised, 1) == 1)
            return;

        Log.Warning("Capture lost: {Reason}", reason);
        CaptureLost?.Invoke(reason);
    }

    public void RegisterUnhandledHandler(Action<NotifyId, ReadOnlySpan<byte>, ExtraPacketData> handler)
    {
        UnhandledHandler = handler;
    }

    public void RegisterUnhandledProxyHandler(Action<ProxyId, ReadOnlySpan<byte>, ExtraPacketData> handler)
    {
        UnhandledProxyHandler = handler;
    }

    public void RegisterNotifyHandler(ulong serviceId, uint methodId, Action<ReadOnlySpan<byte>, ExtraPacketData> handler)
    {
        NotifyHandlers.Add(new NotifyId(serviceId, methodId), handler);
    }

    public void RegisterMatchNotifyHandler(ServiceMethods.MatchNtf methodId, Action<ReadOnlySpan<byte>, ExtraPacketData> handler)
    {
        NotifyHandlers.Add(new NotifyId((ulong)EServiceId.MatchNtf, (uint)methodId), handler);
    }

    public void RegisterWorldNotifyHandler(ServiceMethods.WorldNtf methodId, Action<ReadOnlySpan<byte>, ExtraPacketData> handler)
    {
        NotifyHandlers.Add(new NotifyId((ulong)EServiceId.WorldNtf, (uint)methodId), handler);
    }

    public void RegisterProxyHandler(uint serviceId, uint methodId, Action<ReadOnlySpan<byte>, uint, ExtraPacketData> handler)
    {
        ProxyHandlers.Add(new ProxyId(serviceId, methodId), handler);
    }

    public void RegisterProxyReturnHandler(uint serviceId, uint methodId, Action<ReadOnlySpan<byte>, uint, ExtraPacketData> handler)
    {
        ProxyReturnHandlers.Add(new ProxyId(serviceId, methodId), handler);
    }

    private void DeviceOnOnPacketArrival(object sender, PacketCapture e)
    {
        var rawPacket = e.GetPacket();

        if (IsDebugCaptureFileMode)
        {
            if (LastDebugCapturePacketTime == DateTime.MinValue)
            {
                LastDebugCapturePacketTime = rawPacket.Timeval.Date;
            }
            else
            {
                TimeSpan timeDiff = rawPacket.Timeval.Date.Subtract(LastDebugCapturePacketTime);
                if (timeDiff > TimeSpan.Zero)
                {
                    System.Threading.Thread.Sleep(timeDiff);
                }

                LastDebugCapturePacketTime = rawPacket.Timeval.Date;
            }
        }

        if (PacketCaptured != null)
        {
            try
            {
                PacketCaptured(rawPacket);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "PacketCaptured handler failed");
            }
        }

        ProcessPacket(rawPacket);
    }

    private void ProcessPacket(RawCapture rawPacket)
    {
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        var ipv4 = packet?.Extract<IPv4Packet>();
        if (ipv4 == null)
            return;

        var tcpPacket = packet?.Extract<TcpPacket>();
        if (tcpPacket == null)
            return;

        NumSeenPackets++;
        LastPacketSeenAt = DateTime.Now;

        if (tcpPacket.DestinationPort <= 1000 || tcpPacket.SourcePort <= 1000)
            return;

        if (IsDebugCaptureFileMode || IsReplay || Config.UseRemoteCapture) {
            TcpReassempler.AddPacket(ipv4, tcpPacket, rawPacket.Timeval);
            return;
        }

        var connId = new ConnectionId(ipv4.SourceAddress.ToString(), tcpPacket.SourcePort, ipv4.DestinationAddress.ToString(), tcpPacket.DestinationPort);
        if (!ConnectionFilters.TryGetValue(connId, out var allowed))
        {
            if (IsFromGame(ipv4, tcpPacket)) {
                ConnectionFilters.TryAdd(connId, true);
            }
            else {
                ConnectionFilters.TryAdd(connId, false);
                return;
            }
        }

        if (!allowed)
            return;

        TcpReassempler.AddPacket(ipv4, tcpPacket, rawPacket.Timeval);
    }

    /// <summary>
    /// Feeds a classic pcap file through the exact same reassembly / parsing pipeline as a live capture and returns once every
    /// message in it was emitted (to the registered handlers and <see cref="MessageReceived"/>).
    /// </summary>
    public ReplayStats ReplayFile(string path, CancellationToken cancellationToken = default)
    {
        Config ??= new NetCapConfig();
        IsReplay = true;

        using var reader = new PcapFileReader(path);
        TcpReassempler = new TcpReassembler();
        TcpReassempler.OnNewConnection += OnNewConnection;
        PacketParseTask = Task.Factory.StartNew(ParsePacketsLoop, CancelTokenSrc.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        long packetCount = 0;
        DateTime? firstPacketTime = null;
        DateTime? lastPacketTime = null;

        try
        {
            foreach (var rawPacket in reader.ReadPackets())
            {
                cancellationToken.ThrowIfCancellationRequested();
                packetCount++;
                firstPacketTime ??= rawPacket.Timeval.Date;
                lastPacketTime = rawPacket.Timeval.Date;
                ProcessPacket(rawPacket);

                // Don't let the file reading run arbitrarily far ahead of the parser
                while (RawPacketQueue.Count > MaxReplayQueueLength)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Thread.Sleep(1);
                }
            }

            // End all streams (no FIN may have been captured) and let the readers and the parser finish what is buffered
            TcpReassempler.CompleteAll();
            while (Volatile.Read(ref NumConnectionReaders) > 0 ||
                   Interlocked.Read(ref NumGameMessagesSeen) != Interlocked.Read(ref NumGameMessagesDequeued))
            {
                cancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(2);
            }

            return new ReplayStats(packetCount, firstPacketTime, lastPacketTime);
        }
        finally
        {
            IsStopping = true;
            CancelTokenSrc.Cancel();
            foreach (var conn in TcpReassempler.Connections.Values.ToList())
            {
                TcpReassempler.RemoveConnection(conn, discardPending: true);
            }
            try { PacketParseTask.Wait(); } catch (Exception) { }
        }
    }

    private void OnNewConnection(TcpReassembler.TcpConnection conn)
    {
        // Counted before the task starts, so a replay waiting for the readers can't miss one that is about to start
        Interlocked.Increment(ref NumConnectionReaders);
        var task = Task.Factory.StartNew(async () =>
        {
            ulong consumed = 0;
            long streamIndex = 0;
            // A removed connection is not cancelled, its writer is completed so the reader first drains what is still buffered
            while (!CancelTokenSrc.IsCancellationRequested && !conn.CancelTokenSrc.IsCancellationRequested) {
                var buff = await conn.Pipe.Reader.ReadAtLeastAsync(6);
                if (buff.IsCanceled || buff.Buffer.Length < 6)
                    break;

                Span<byte> header = new byte[6];
                buff.Buffer.Slice(0, 6).CopyTo(header);
                var len = BinaryPrimitives.ReadUInt32BigEndian(header);
                var rawMsgType = BinaryPrimitives.ReadInt16BigEndian(header[4..]);
                var msgType = (rawMsgType & 0x7FFF);
                conn.Pipe.Reader.AdvanceTo(buff.Buffer.Start);

                if (len < 6 || len > MaxGameMessageLength || msgType > (int)MsgTypeId.UNK2)
                {
                    // The stream is misaligned; waiting for `len` bytes would hang silently forever, so drop it and re-sync
                    Log.Logger.Warning("{EndPoint} invalid message header (len {Len}, type {MsgType}), removing stream to resync", conn.EndPoint, len, msgType);
                    TcpReassempler.RemoveConnection(conn, discardPending: true);
                    break;
                }

                /*
                if (msgType > 20)
                {
                    var msg = $"!! Message Type ({msgType}) Was not in expected range, maybe this is not a game connection! {conn.EndPoint} -> {conn.DestEndPoint}";
                    Debug.WriteLine(msg);
                    ImportantLogMsgs.Add(msg);
                    Log.Logger.Information(msg);
                    var connId = new ConnectionId(conn.EndPoint.Address.ToString(), (ushort)conn.EndPoint.Port, conn.DestEndPoint.Address.ToString(), (ushort)conn.DestEndPoint.Port);
                    //ConnectionFilters[connId] = false;
                    TcpReassempler.RemoveConnection(connId);
                    break;
                }*/

                var msgBuff = await conn.Pipe.Reader.ReadAtLeastAsync((int)len);
                if (msgBuff.IsCanceled || msgBuff.Buffer.Length < len)
                    break;

                // The message is complete once the segment holding its last byte arrived
                consumed += len;
                var arrivalTime = conn.LastPacketTime;
                while (conn.SegmentTimes.TryPeek(out var segment))
                {
                    if (segment.EndOffset < consumed)
                    {
                        conn.SegmentTimes.TryDequeue(out _);
                    }
                    else
                    {
                        arrivalTime = segment.Time;
                        break;
                    }
                }

                var rawPacket = RawPacketPool.Get();
                rawPacket.Set((int)len);
                rawPacket.LastPacketTime = arrivalTime;
                rawPacket.Source = conn.EndPoint;
                rawPacket.Destination = conn.DestEndPoint;
                rawPacket.StreamId = conn.Id;
                rawPacket.StreamIndex = streamIndex++;
                rawPacket.StreamOffset = (long)(consumed - len);
                msgBuff.Buffer.Slice(0, len).CopyTo(rawPacket.Data.AsSpan()[..(int)len]);
                RawPacketQueue.Enqueue(rawPacket);
                conn.Pipe.Reader.AdvanceTo(msgBuff.Buffer.GetPosition(len));
                Interlocked.Increment(ref NumGameMessagesSeen);
                LastGameMessageAt = DateTime.Now;
            }
        }, CancelTokenSrc.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap().ContinueWith(t =>
        {
            // Also runs when the reader threw or never started, so the reader count always returns to zero
            if (t.IsFaulted)
                Log.Logger.Error(t.Exception, "{EndPoint} reader failed", conn.EndPoint);
            try { conn.Pipe.Reader.Complete(); } catch (Exception) { }
            Interlocked.Decrement(ref NumConnectionReaders);
            Log.Logger.Information($"{conn.EndPoint} finished reading");
        }, TaskScheduler.Default);
    }
    
    private void ParsePacketsLoop()
    {
        while (!CancelTokenSrc.IsCancellationRequested)
        {
            if (RawPacketQueue.TryDequeue(out var rawPacket))
            {
                Ctx.Time = rawPacket.LastPacketTime;
                Ctx.Source = rawPacket.Source;
                Ctx.Destination = rawPacket.Destination;
                Ctx.StreamId = rawPacket.StreamId;
                Ctx.StreamIndex = rawPacket.StreamIndex;
                Ctx.StreamOffset = rawPacket.StreamOffset;
                Ctx.SubIndex = 0;
                Ctx.Container = MessageContainer.None;
                Ctx.FrameId = null;
                Ctx.ContainerCompressed = false;
                ParseDepth = 0;
                try
                {
                    ParsePacket(rawPacket.Data[..rawPacket.Len], rawPacket.LastPacketTime);
                }
                catch (Exception ex)
                {
                    // One malformed message must not kill the parser for the rest of the session
                    Log.Logger.Error(ex, "Error parsing message from {Source}", rawPacket.Source);
                }

                // Important to return the packet to the pool!
                rawPacket.Return();
                RawPacketPool.Return(rawPacket);
                NumGameMessagesDequeued++;
            }
            else
            {
                Task.Delay(10).Wait();
            }
        }
    }

    /// <summary>State of the top level message currently being parsed (parser thread only), read by <see cref="Emit"/>.</summary>
    private sealed class ParseContext
    {
        public DateTime Time;
        public IPEndPoint? Source;
        public IPEndPoint? Destination;
        public long StreamId;
        public long StreamIndex;
        public long StreamOffset;
        public int WireLength;
        public int SubIndex;
        public MessageContainer Container;
        public uint? FrameId;
        public bool ContainerCompressed;
    }

    private void Emit(MsgTypeId kind, bool compressed, bool decompressFailed, ulong? serviceId, uint? methodId,
        uint? stubId, uint? returnUid, uint? aux, ReadOnlySpan<byte> payload, bool truncated = false)
    {
        var tap = MessageReceived;
        if (tap == null)
            return;

        try
        {
            tap(new GameMessageInfo
            {
                Time = Ctx.Time,
                Source = Ctx.Source,
                Destination = Ctx.Destination,
                StreamId = Ctx.StreamId,
                StreamIndex = Ctx.StreamIndex,
                StreamOffset = Ctx.StreamOffset,
                WireLength = Ctx.WireLength,
                SubIndex = Ctx.SubIndex,
                Kind = kind,
                Container = Ctx.Container,
                FrameId = Ctx.FrameId,
                ContainerCompressed = Ctx.ContainerCompressed,
                Compressed = compressed,
                DecompressFailed = decompressFailed,
                Truncated = truncated,
                ServiceId = serviceId,
                MethodId = methodId,
                StubId = stubId,
                ReturnUid = returnUid,
                Aux = aux,
            }, payload);
        }
        catch (Exception ex)
        {
            Log.Logger.Warning(ex, "MessageReceived handler failed");
        }

        Ctx.SubIndex++;
    }

    private void ParsePacket(ReadOnlySpan<byte> data, DateTime lastPacketTime)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            var msgData = data[offset..];
            Ctx.WireLength = msgData.Length;
            if (msgData.Length < 6)
            {
                Emit(MsgTypeId.None, false, false, null, null, null, null, null, msgData, truncated: true);
                return;
            }

            var len = BinaryPrimitives.ReadUInt32BigEndian(msgData);

            if (len < 6 || len > msgData.Length)
            {
                Emit(MsgTypeId.None, false, false, null, null, null, null, null, msgData, truncated: true);
                return;
            }

            var rawMsgType = BinaryPrimitives.ReadInt16BigEndian(msgData[4..]);
            var isCompressed = (rawMsgType & 0x8000) != 0;
            var msgType = (MsgTypeId)(rawMsgType & 0x7FFF);
            var msgPayload = msgData.Slice(6, (int)len - 6);
            offset += (int)len;
            Ctx.WireLength = (int)len;

            switch (msgType)
            {
                case MsgTypeId.Notify:
                    ParseNotify(msgPayload, isCompressed, lastPacketTime);
                    break;
                case MsgTypeId.FrameDown:
                    ParseFrameDown(msgPayload, isCompressed, lastPacketTime);
                    break;
                case MsgTypeId.Call:
                    ParseCall(msgPayload, isCompressed, lastPacketTime);
                    break;
                case MsgTypeId.Return:
                    ParseReturn(msgPayload, isCompressed, lastPacketTime);
                    break;
                case MsgTypeId.FrameUp:
                    ParseFrameUp(msgPayload, isCompressed, lastPacketTime);
                    break;
                case MsgTypeId.None:
                    Emit(msgType, isCompressed, false, null, null, null, null, null, msgPayload);
                    break;
                case MsgTypeId.Echo:
                    // Empty packets sent two at a time about once per second
                    Emit(msgType, isCompressed, false, null, null, null, null, null, msgPayload);
                    break;
                case MsgTypeId.UNK1:
                    // Counter that increments once per 5 seconds
                    Emit(msgType, isCompressed, false, null, null, null, null, null, msgPayload);
                    break;
                case MsgTypeId.UNK2:
                    // Counter that increments about once per second
                    Emit(msgType, isCompressed, false, null, null, null, null, null, msgPayload);
                    break;
                default:
                    Log.Information("Got an unknown message type: {msgType}", msgType);
                    Emit(msgType, isCompressed, false, null, null, null, null, null, msgPayload);
                    break;
            }
        }
    }

    private void ParseFrameDown(ReadOnlySpan<byte> data, bool isCompressed, DateTime lastPacketTime)
    {
        if (data.Length < 4)
        {
            Emit(MsgTypeId.FrameDown, isCompressed, false, null, null, null, null, null, data, truncated: true);
            return;
        }

        var seqNum = BinaryPrimitives.ReadUInt32BigEndian(data);
        var (previousContainer, previousFrameId, previousCompressed) = (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed);
        (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed) = (MessageContainer.FrameDown, seqNum, isCompressed);

        if (isCompressed)
        {
            var decompressed = Decompress(data[4..]);
            if (!decompressed.IsEmpty)
            {
                ParseDepth++;
                ParsePacket(decompressed, lastPacketTime);
                ParseDepth--;
            }
            else
            {
                Emit(MsgTypeId.FrameDown, true, true, null, null, null, null, null, data[4..]);
            }
        }
        else
        {
            ParseDepth++;
            ParsePacket(data[4..], lastPacketTime);
            ParseDepth--;
        }

        (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed) = (previousContainer, previousFrameId, previousCompressed);
    }

    /// <summary>
    /// Notify layout: [u64 service][u32 stub][u32 method][payload]. Server messages dispatch to the notify handlers,
    /// the same layout inside a FrameUp (<paramref name="fromClient"/>) is client to server and dispatches to the proxy handlers.
    /// </summary>
    private void ParseNotify(ReadOnlySpan<byte> data, bool isCompressed, DateTime lastPacketTime, bool fromClient = false)
    {
        //byte[] debugHeaders = data.ToArray();

        if (data.Length < 16)
        {
            Emit(MsgTypeId.Notify, isCompressed, false, null, null, null, null, null, data, truncated: true);
            return;
        }

        var serviceUuid = BinaryPrimitives.ReadUInt64BigEndian(data);
        var stubId = BinaryPrimitives.ReadUInt32BigEndian(data[8..]);
        var methodId = BinaryPrimitives.ReadUInt32BigEndian(data[12..]);

        var msgData = data[16..];
        if (isCompressed)
        {
            msgData = Decompress(msgData);

            if (msgData.IsEmpty)
            {
                Log.Logger.Warning("Error decompressing data for {serviceUuid}, {stubId}, {methodId}", serviceUuid, stubId, methodId);
                Emit(MsgTypeId.Notify, true, true, serviceUuid, methodId, stubId, null, null, data[16..]);
                return;
            }
        }

        Emit(MsgTypeId.Notify, isCompressed, false, serviceUuid, methodId, stubId, null, null, msgData);

        if (fromClient)
        {
            DispatchProxy(new ProxyId((uint)serviceUuid, methodId), msgData, stubId, lastPacketTime);
            return;
        }

        if (!Enum.IsDefined(typeof(EServiceId), serviceUuid))
        {
            Log.Logger.Information($"Unknown ServiceId = {serviceUuid} MethodId = {methodId}");
        }
        else
        {
            //Log.Logger.Information($"ParseNotify: S:{serviceUuid}({(EServiceId)serviceUuid}) Stub:{stubId} M:{methodId} MsgDataLen:{msgData.Length} Len={data.Length}");
        }

        var id = new NotifyId(serviceUuid, methodId);
        if (NotifyHandlers.TryGetValue(id, out var handler))
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            handler(msgData, extraData);
        }
        else if (UnhandledHandler != null)
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            UnhandledHandler(id, msgData, extraData);
        }

        //Log.Information("Service UUID: {ServiceUuid}, Stub ID: {StubId}, Method ID: {MethodId}, IsCompressed: {IsCompressed}", serviceUuid, stubId, methodId, isCompressed);
    }

    private void DispatchProxy(ProxyId id, ReadOnlySpan<byte> msgData, uint returnUid, DateTime lastPacketTime)
    {
        if (ProxyHandlers.TryGetValue(id, out var handler))
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            handler(msgData, returnUid, extraData);
        }
        else if (UnhandledProxyHandler != null)
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            UnhandledProxyHandler(id, msgData, extraData);
        }
    }

    /// <summary>Call layout: [u64 service][u32 sub id][u32 return uid][u32 method][payload].</summary>
    private void ParseCall(ReadOnlySpan<byte> data, bool isCompressed, DateTime lastPacketTime)
    {
        //byte[] debugHeaders = data.ToArray();

        if (data.Length < 20)
        {
            Emit(MsgTypeId.Call, isCompressed, false, null, null, null, null, null, data, truncated: true);
            return;
        }

        var proxyServiceId = BinaryPrimitives.ReadUInt64BigEndian(data);
        var subId = BinaryPrimitives.ReadUInt32BigEndian(data[8..]);
        var returnUid = BinaryPrimitives.ReadUInt32BigEndian(data[12..]);
        var proxyMethodId = BinaryPrimitives.ReadUInt32BigEndian(data[16..]);
        var msgData = data[20..];

        if (isCompressed)
        {
            msgData = Decompress(msgData);

            if (msgData.IsEmpty)
            {
                Log.Logger.Warning("Error decompressing data for {proxyServiceId}, {subId}, {returnUid}, {proxyMethodId}", proxyServiceId, subId, returnUid, proxyMethodId);
                Emit(MsgTypeId.Call, true, true, proxyServiceId, proxyMethodId, subId, returnUid, null, data[20..]);
                return;
            }
        }

        Emit(MsgTypeId.Call, isCompressed, false, proxyServiceId, proxyMethodId, subId, returnUid, null, msgData);

        ProxyReturnsDictionary.AddOrUpdate(returnUid, new ProxyId((uint)proxyServiceId, proxyMethodId), (key, value) => new ProxyId((uint)proxyServiceId, proxyMethodId));

        string loggedMsg = "";
        if (msgData.Length > 0)
        {
            if (msgData.Length > 50)
            {
                loggedMsg = Convert.ToHexString(msgData[0..50]);
            }
            else
            {
                loggedMsg = Convert.ToHexString(msgData);
            }
        }

        //Log.Logger.Information($"ParseCall: I:{proxyServiceId} S:{subId} R:{returnUid} M:{proxyMethodId} Len={data.Length} IsCompressed={isCompressed}{(loggedMsg.Length > 0 ? $"\nData: [{loggedMsg}]" : "")}");

        var id = new ProxyId((uint)proxyServiceId, proxyMethodId);
        if (ProxyHandlers.TryGetValue(id, out var handler))
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            handler(msgData, returnUid, extraData);
        }
        else if (UnhandledProxyHandler != null)
        {
            var extraData = new ExtraPacketData(lastPacketTime);
            UnhandledProxyHandler(id, msgData, extraData);
        }
    }

    /// <summary>
    /// FrameUp: [u32 uuid] followed by entries of [u32 length incl. this field][u16 type|0x8000 compressed][entry body].
    /// An entry is laid out exactly like the top level message of that type: type 2 is a Notify, type 1 a Call.
    /// </summary>
    private void ParseFrameUp(ReadOnlySpan<byte> data, bool isCompressed, DateTime lastPacketTime)
    {
        //byte[] debugHeaders = data.ToArray();

        // Only the uuid is checked here, a compressed body can be smaller than one uncompressed entry; the entries are bounds checked below
        if (data.Length < 4)
        {
            // FrameUp is unexpectedly too small
            byte[] debugHeaders = data.ToArray();
            Log.Logger.Information($"ParseFrameUp: [{Convert.ToHexString(debugHeaders)}] Len={data.Length}");
            Emit(MsgTypeId.FrameUp, isCompressed, false, null, null, null, null, null, data, truncated: true);
            return;
        }

        var uuid = BinaryPrimitives.ReadUInt32BigEndian(data);
        var body = data[4..];
        var (previousContainer, previousFrameId, previousCompressed) = (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed);
        (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed) = (MessageContainer.FrameUp, uuid, isCompressed);

        if (isCompressed)
        {
            body = Decompress(body);
            if (body.IsEmpty)
            {
                Emit(MsgTypeId.FrameUp, true, true, null, null, null, null, null, data[4..]);
                (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed) = (previousContainer, previousFrameId, previousCompressed);
                return;
            }
        }

        ParseDepth++;
        int offset = 0;
        while (offset + 6 <= body.Length)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(body[offset..]);
            if (length < 6 || length > body.Length - offset)
            {
                Log.Logger.Warning("ParseFrameUp: malformed entry length {Length} at {Offset}/{Total}, dropping rest of frame", length, offset, body.Length);
                break;
            }

            var rawType = BinaryPrimitives.ReadUInt16BigEndian(body[(offset + 4)..]);
            var entryCompressed = (rawType & 0x8000) != 0;
            var entryType = (MsgTypeId)(rawType & 0x7FFF);
            var entry = body.Slice(offset + 6, (int)length - 6);
            offset += (int)length;
            Ctx.WireLength = (int)length;

            switch (entryType)
            {
                case MsgTypeId.Notify:
                    ParseNotify(entry, entryCompressed, lastPacketTime, fromClient: true);
                    break;
                case MsgTypeId.Call:
                    ParseCall(entry, entryCompressed, lastPacketTime);
                    break;
                default:
                    Emit(entryType, entryCompressed, false, null, null, null, null, null, entry);
                    break;
            }
        }
        if (offset < body.Length)
        {
            Ctx.WireLength = body.Length - offset;
            Emit(MsgTypeId.None, false, false, null, null, null, null, null, body[offset..], truncated: true);
        }
        ParseDepth--;

        (Ctx.Container, Ctx.FrameId, Ctx.ContainerCompressed) = (previousContainer, previousFrameId, previousCompressed);
    }

    private void ParseReturn(ReadOnlySpan<byte> data, bool isCompressed, DateTime lastPacketTime)
    {
        //byte[] debugHeaders = data.ToArray();

        if (data.Length < 12)
        {
            byte[] debugHeaders = data.ToArray();
            Log.Logger.Information($"ParseReturn: [{Convert.ToHexString(debugHeaders)}] Len={data.Length}");
            Emit(MsgTypeId.Return, isCompressed, false, null, null, null, null, null, data, truncated: true);
            return;
        }

        var subId = BinaryPrimitives.ReadUInt32BigEndian(data);
        var returnUid = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);
        var thirdId = BinaryPrimitives.ReadUInt32BigEndian(data[8..]);

        var msgData = data[12..];

        var hasCall = ProxyReturnsDictionary.TryRemove(returnUid, out var frameUp);
        ulong? callService = hasCall ? frameUp!.ServiceId : null;
        uint? callMethod = hasCall ? frameUp!.MethodId : null;

        if (isCompressed)
        {
            msgData = Decompress(msgData);

            if (msgData.IsEmpty)
            {
                Log.Logger.Warning($"Error decompressing data for {subId}, {returnUid}, {thirdId}");
                Emit(MsgTypeId.Return, true, true, callService, callMethod, subId, returnUid, thirdId, data[12..]);
                return;
            }
        }

        // The tap gets the payload untouched, the handlers below the legacy "find where the protobuf starts" heuristic
        Emit(MsgTypeId.Return, isCompressed, false, callService, callMethod, subId, returnUid, thirdId, msgData);

        int protoStart = 0;
        int range = Math.Min(msgData.Length, 4);
        for (int i = 0; i < range; i++)
        {
            if (msgData[i] == 0x0A)
            {
                // Found final potential start
                protoStart = i;
            }
        }

        //Log.Logger.Information($"ParseReturn: S:{subId} R:{returnUid} T:{thirdId} Start={protoStart} Len={data.Length} IsCompressed={isCompressed}");

        if (hasCall)
        {
            var id = new ProxyId(frameUp!.ServiceId, frameUp.MethodId);
            if (ProxyReturnHandlers.TryGetValue(id, out var handler))
            {
                ReadOnlySpan<byte> msgDataFinal = msgData[protoStart..];
                var extraData = new ExtraPacketData(lastPacketTime);
                handler(msgDataFinal, returnUid, extraData);
            }
        }
    }

    private ReadOnlySpan<byte> Decompress(ReadOnlySpan<byte> data)
    {
        try
        {
            var decompressedLen = _decompressor.Unwrap(data, DecompressionScratchBuffer.AsSpan());
            return DecompressionScratchBuffer.AsSpan()[..decompressedLen];
        }
        catch (Exception ex)
        {
            Log.Logger.Warning(ex, "Error decompressing data of Len: {Len}, DecompressionScratchBuffer Size: {ScratchSize}", data.Length, DecompressionScratchBuffer.Length);
            try
            {
                return _decompressor.Unwrap(data);
            }
            catch (Exception ex2)
            {
                Log.Logger.Error(ex2, "Error performing fallback decompressing data of Len: {Len}", data.Length);
                return [];
            }
        }
    }

    private bool IsFromGame(IPv4Packet ip, TcpPacket tcp)
    {
        var sw = Stopwatch.StartNew();
        var conns = Utils.GetTCPConnectionsForExe(Config.ExeNames);
        /*var isGameConnection = conns.Any((x =>
            (x.LocalAddress == ip.SourceAddress.ToString() && x.LocalPort == tcp.SourcePort) ||
            (x.RemoteAddress == ip.SourceAddress.ToString() && x.RemotePort == tcp.SourcePort) ||
            (x.LocalAddress == ip.DestinationAddress.ToString() && x.LocalPort == tcp.DestinationPort) ||
            (x.RemoteAddress == ip.DestinationAddress.ToString() && x.RemotePort == tcp.DestinationPort)));*/

        var isGameConnection = conns.Any((x =>
            (x.LocalAddress == ip.SourceAddress.ToString() && x.LocalPort == tcp.SourcePort) ||
            (x.RemoteAddress == ip.SourceAddress.ToString() && x.RemotePort == tcp.SourcePort)));

        sw.Stop();
        Log.Logger.Debug($"Checking {ip.SourceAddress}:{tcp.SourcePort} > {ip.DestinationAddress}:{tcp.DestinationPort} is game connection: {isGameConnection}, took {sw.ElapsedMilliseconds}ms");
        
        return isGameConnection;
    }

    /// <summary>Waits until every message the connection readers queued so far was parsed (best effort, for a graceful shutdown).</summary>
    public bool WaitUntilParsed(TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (Interlocked.Read(ref NumGameMessagesSeen) != Interlocked.Read(ref NumGameMessagesDequeued))
        {
            if (sw.Elapsed >= timeout)
                return false;
            Thread.Sleep(5);
        }
        return true;
    }

    public void Stop()
    {
        IsStopping = true;
        CancelTokenSrc.Cancel();

        // Ends the connection readers, otherwise they stay parked on their pipes forever
        if (TcpReassempler != null)
        {
            foreach (var conn in TcpReassempler.Connections.Values.ToList())
            {
                TcpReassempler.RemoveConnection(conn, discardPending: true);
            }
        }

        if (CaptureDevice != null)
        {
            // The device may already be dead (e.g. dropped remote connection) so these can throw
            try { CaptureDevice.OnCaptureStopped -= DeviceOnCaptureStopped; } catch (Exception) { }

            Log.Information("Stopping capture device (started: {Started})", CaptureDevice.Started);
            try { CaptureDevice.StopCapture(); } catch (Exception ex) { Log.Warning(ex, "Error stopping capture device"); }

            // Closing the pcap handle while the capture thread is still inside libpcap is a use-after-free that
            // crashes the whole process natively (PAL_SEHException). If the thread didn't stop, leak the handle instead.
            bool stillRunning = false;
            try { stillRunning = CaptureDevice.Started; } catch (Exception) { }
            if (stillRunning)
            {
                Log.Error("Capture thread did not stop, not closing the device to avoid a native crash");
                StopFailed = true;
            }
            else
            {
                Log.Information("Closing capture device");
                try { CaptureDevice.Close(); } catch (Exception ex) { Log.Warning(ex, "Error closing capture device"); }
            }
            ConnectionFilters.Clear();

            Log.Information("Capture device stopped");
        }
    }

    public void PrintCaptureDevices()
    {
        var devices = CaptureDeviceList.Instance;
        foreach (var liveDevice in devices)
        {
            var dev = (LibPcapLiveDevice)liveDevice;
            Log.Information("Device: {DeviceName}, {FriendlyName}", dev.Name, dev.Interface?.FriendlyName);
        }
    }

    private ICaptureDevice GetCaptureDevice()
    {
        var devices = CaptureDeviceList.Instance;

        try
        {
            foreach (var liveDevice in devices)
            {
                var dev = (LibPcapLiveDevice)liveDevice;
                if (dev.Name == Config.CaptureDeviceName)
                {
                    Log.Information("Matched capture device: {DeviceName}, {FriendlyName}", dev.Name, dev.Interface?.FriendlyName);
                    return dev;
                }
            }

            Log.Information("No matched capture device, trying to find Ethernet");
            var ethernet = devices.FirstOrDefault(x => ((LibPcapLiveDevice)x).Interface?.FriendlyName == "Ethernet");
            if (ethernet != null)
            {
                Log.Information("Found Ethernet named capture device, using it: {DeviceName}, {FriendlyName}", ethernet.Name, ((LibPcapLiveDevice)ethernet).Interface?.FriendlyName);
                return ethernet;
            }
        }
        catch (Exception e)
        {
            Log.Error(e, "Error getting capture device");
            throw;
        }

        var device = devices[0];
        Log.Information("No matched capture device, using first found: {DeviceName}, {FriendlyName}", device.Name, ((LibPcapLiveDevice)device).Interface?.FriendlyName);
        return device;
    }

    private ICaptureDevice GetRemoteCaptureDevice()
    {
        var remoteInterfaces = PcapInterface.GetAllPcapInterfaces($"rpcap://{Config.RemoteCaptureHost}:{Config.RemoteCapturePort}/", null);

        foreach (var iface in remoteInterfaces)
        {
            Log.Information("Remote capture interface: {Interface}", iface.ToString());
        }

        var selected = remoteInterfaces[Config.RemoteCaptureDeviceIndex];
        Log.Information("Using remote capture interface [{Index}]: {Interface}", Config.RemoteCaptureDeviceIndex, selected.ToString());
        return new LibPcapLiveDevice(selected);
    }

    public string GetFilterString(IEnumerable<TcpHelper.TcpRow> conns)
    {
        var connLines = conns.DistinctBy(x => x.RemoteAddress).Select(x => $"(tcp and src host {x.RemoteAddress} or dst host {x.RemoteAddress})");
        var filterStr = string.Join(" or ", connLines);
        return filterStr;
    }
}

public class PendingConnState(IPAddress addr)
{
    public IPAddress IPAddress { get; set; } = addr;
    public DateTime FirstSeenAt { get; set; } = DateTime.Now;
    public bool? IsGameConnection = null;
}