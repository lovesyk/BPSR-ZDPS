using System.Net;

namespace BPSR_ZDPSLib;

public enum MessageContainer : byte
{
    None = 0,
    FrameDown = 1,
    FrameUp = 2,
}

/// <summary>
/// Everything known about a single game message at the point it was framed, independent of whether a handler is registered for it.
/// </summary>
public sealed class GameMessageInfo
{
    /// <summary>Capture time of the TCP segment that completed this message (UTC).</summary>
    public DateTime Time { get; init; }
    public IPEndPoint? Source { get; init; }
    public IPEndPoint? Destination { get; init; }
    /// <summary>Id of the directional TCP stream instance, unique per <see cref="NetCap"/> and assigned in packet order.</summary>
    public long StreamId { get; init; }
    /// <summary>Ordinal of the top level message within its stream.</summary>
    public long StreamIndex { get; init; }
    /// <summary>Byte offset of the top level message within its stream.</summary>
    public long StreamOffset { get; init; }
    /// <summary>Length field of the message header (header included, compressed size), for a message inside a frame the entry length within the frame.</summary>
    public int WireLength { get; init; }
    /// <summary>Ordinal of this message within its top level message (always 0 unless inside a frame).</summary>
    public int SubIndex { get; init; }
    public MsgTypeId Kind { get; init; }
    public MessageContainer Container { get; init; }
    /// <summary>FrameDown sequence number / FrameUp uuid.</summary>
    public uint? FrameId { get; init; }
    /// <summary>The enclosing FrameDown / FrameUp was compressed.</summary>
    public bool ContainerCompressed { get; init; }
    public bool Compressed { get; init; }
    /// <summary>True when decompression was required but failed, the payload is then still the compressed bytes.</summary>
    public bool DecompressFailed { get; init; }
    /// <summary>The message was too short for its header (or its length exceeded the data), the payload is the raw remaining bytes.</summary>
    public bool Truncated { get; init; }
    public ulong? ServiceId { get; init; }
    public uint? MethodId { get; init; }
    /// <summary>Notify stub id, or the "sub id" of a Call / Return.</summary>
    public uint? StubId { get; init; }
    public uint? ReturnUid { get; init; }
    /// <summary>Third header field of a Return (meaning not yet known).</summary>
    public uint? Aux { get; init; }
}

public delegate void GameMessageHandler(GameMessageInfo info, ReadOnlySpan<byte> payload);
