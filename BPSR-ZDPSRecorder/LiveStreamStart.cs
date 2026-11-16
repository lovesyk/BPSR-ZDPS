using System.Net;
using BPSR_ZDPSLib;
using SharpPcap;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// Makes a live capture keep the first message of every connection whose SYN was captured.
/// ZDPSLib only starts reading a stream at a TCP segment holding exactly one message, so a first message that spans
/// segments (e.g. the gateway's Login Call) is lost. Here the stream is started at the SYN's sequence number + 1 instead,
/// using only public members of the lib: <see cref="NetCap.PacketCaptured"/> runs on the capture thread right before the
/// packet is handed to the reassembler, which creates the connection (and raises OnNewConnection) on that same thread.
/// </summary>
public sealed class LiveStreamStart
{
    private readonly NetCap _netCap;
    // Stream start (SYN seq + 1) per sending endpoint, waiting for the reassembler to create the connection
    private readonly Dictionary<IPEndPoint, uint> _pending = new();
    private bool _hooked;
    private bool _currentIsSyn;

    private LiveStreamStart(NetCap netCap) => _netCap = netCap;

    /// <summary>Call before <see cref="NetCap.Start"/>.</summary>
    public static void Attach(NetCap netCap)
    {
        var tracker = new LiveStreamStart(netCap);
        netCap.PacketCaptured += tracker.OnPacketCaptured;
    }

    private void OnPacketCaptured(RawCapture packet)
    {
        // The reassembler is created in Start() before the capture begins, so it exists by the first packet
        if (!_hooked && _netCap.TcpReassempler != null)
        {
            _netCap.TcpReassempler.OnNewConnection += OnNewConnection;
            _hooked = true;
        }

        _currentIsSyn = false;
        if (!TcpFrame.TryParse(packet.LinkLayerType, packet.Data, out var frame) || !frame.IsReassembled)
            return;

        if (frame.Syn)
        {
            _pending[frame.Source] = unchecked(frame.Seq + 1);
            _currentIsSyn = true;
        }
        else if (frame.FinOrRst)
        {
            _pending.Remove(frame.Source);
        }
    }

    private void OnNewConnection(TcpReassembler.TcpConnection conn)
    {
        // The reassembler also creates a connection for the SYN itself and drops it right away; the start is applied to the
        // one created by the next packet. It is used once only: a connection re-created later (after a stall) must not wait
        // for bytes that are long gone, it resyncs the lib's usual way instead.
        if (_currentIsSyn || !_pending.Remove(conn.EndPoint, out var start))
            return;

        conn.NextExpectedSeq = start;
        conn.IsSynced = true;
    }
}
