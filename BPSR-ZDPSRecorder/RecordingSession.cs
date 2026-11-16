using BPSR_ZDPSLib;
using Serilog;
using SharpPcap;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// One live capture run: writes every captured packet to a new pcap file and feeds the parsed messages to the database.
/// The pcap file (and its database row) is only created once the first packet arrives, so retries against an unreachable capture host leave nothing behind.
/// </summary>
public sealed class RecordingSession(RecorderConfig config, RecorderDatabase db) : IDisposable
{
    private readonly object _lock = new();
    // Separate from _lock: enqueueing can block on a full database queue, which must not stall the capture thread
    private readonly object _messageLock = new();
    private PcapFileWriter? _pcap;
    private RecorderDatabase.CaptureHandle? _capture;
    private string? _pcapPath;
    private DateTime? _firstPacketTime;
    private DateTime? _lastPacketTime;
    private Timer? _flushTimer;
    private bool _finished;
    private bool _messagesClosed;

    public NetCap NetCap { get; } = new();

    public void Start(NetCapConfig netCapConfig)
    {
        NetCap.Init(netCapConfig);
        NetCap.PacketCaptured += OnPacketCaptured;
        NetCap.MessageReceived += OnMessage;
        LiveStreamStart.Attach(NetCap);
        NetCap.Start();
        _flushTimer = new Timer(_ => { try { _pcap?.Flush(); } catch (Exception) { } }, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    private void OnPacketCaptured(RawCapture packet)
    {
        lock (_lock)
        {
            if (_finished)
                return;

            if (_pcap == null)
            {
                Directory.CreateDirectory(config.CaptureDirectory);
                var name = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}.pcap";
                for (var i = 1; File.Exists(Path.Combine(config.CaptureDirectory, name)); i++)
                    name = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{i}.pcap";

                _pcapPath = Path.Combine(config.CaptureDirectory, name);
                _pcap = new PcapFileWriter(_pcapPath, packet.LinkLayerType);
                _firstPacketTime = packet.Timeval.Date;
                var filter = string.IsNullOrWhiteSpace(config.RemoteCaptureFilter) ? "" : $" filter \"{config.RemoteCaptureFilter}\"";
                var source = $"rpcap://{config.RemoteCaptureHost}:{config.RemoteCapturePort} device {config.RemoteCaptureDeviceIndex}{filter}";
                Volatile.Write(ref _capture, db.BeginCapture(name, source));
                Log.Information("Recording to {Path}", _pcapPath);
            }

            _pcap.Write(packet.Timeval, packet.Data, packet.PacketLength);
            _lastPacketTime = packet.Timeval.Date;
        }
    }

    private void OnMessage(GameMessageInfo info, ReadOnlySpan<byte> payload)
    {
        var capture = Volatile.Read(ref _capture);
        if (capture == null)
            return;

        // Once the capture is finished its rows are final; a message the parser still emits while stopping is dropped (it is in the pcap)
        lock (_messageLock)
        {
            if (!_messagesClosed)
                db.Enqueue(capture, info, payload);
        }
    }

    /// <summary>Stops the capture (the caller already did, or does so concurrently), closes the pcap and finalizes the database rows.</summary>
    public async Task FinishAsync()
    {
        RecorderDatabase.CaptureHandle? capture;
        long packets = 0;
        long bytes = 0;
        lock (_lock)
        {
            if (_finished)
                return;
            _finished = true;

            capture = _capture;
            if (_pcap != null)
            {
                packets = _pcap.PacketCount;
                _pcap.Dispose();
                bytes = new FileInfo(_pcapPath!).Length;
            }
        }

        if (_flushTimer != null)
            await _flushTimer.DisposeAsync();

        lock (_messageLock)
        {
            _messagesClosed = true;
        }

        if (capture != null)
        {
            await db.EndCapture(capture, _firstPacketTime, _lastPacketTime, packets, bytes);
            Log.Information("Finished {Path}: {Packets} packets", _pcapPath, packets);
        }
    }

    public void Dispose()
    {
        _flushTimer?.Dispose();
        lock (_lock)
        {
            _finished = true;
            _pcap?.Dispose();
        }
    }
}
