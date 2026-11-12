namespace BPSR_ZDPSRecorder;

public class RecorderConfig
{
    public string RemoteCaptureHost { get; set; } = "192.168.1.100";
    public int RemoteCapturePort { get; set; } = 2002;
    public int RemoteCaptureDeviceIndex { get; set; } = 0;

    /// <summary>
    /// Extra BPF filter, applied on top of "tcp and not portrange 0-1000". Everything matching it ends up in the pcap,
    /// so narrow it down (e.g. "host 1.2.3.4") if the capture device sees more than the game.
    /// </summary>
    public string RemoteCaptureFilter { get; set; } = string.Empty;

    /// <summary>Where the raw .pcap files are written to (and read from when regenerating).</summary>
    public string CaptureDirectory { get; set; } = "/data/captures";

    /// <summary>SQLite database that receives one row per game message. Created when missing.</summary>
    public string DatabasePath { get; set; } = "/data/recorder.db";

    /// <summary>Additionally store the payloads of messages ZDPSLib knows the protobuf type of as JSON (makes the database considerably larger).</summary>
    public bool StoreDecodedJson { get; set; } = true;
}
