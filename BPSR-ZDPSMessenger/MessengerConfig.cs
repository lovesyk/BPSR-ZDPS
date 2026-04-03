namespace BPSR_ZDPSMessenger;

public class MessengerConfig
{
    public string RemoteCaptureHost { get; set; } = "192.168.1.100";
    public int RemoteCapturePort { get; set; } = 2002;
    public int RemoteCaptureDeviceIndex { get; set; } = 0;
    public string RemoteCaptureFilter { get; set; } = string.Empty;

    public string ApiEndpoint { get; set; } = string.Empty;

    public ChatChannelFilter AllowedChannels { get; set; } = new();
}

public class ChatChannelFilter
{
    public bool ChannelNull { get; set; } = false;
    public bool ChannelWorld { get; set; } = false;
    public bool ChannelScene { get; set; } = false;
    public bool ChannelTeam { get; set; } = false;
    public bool ChannelUnion { get; set; } = false;
    public bool ChannelPrivate { get; set; } = false;
    public bool ChannelGroup { get; set; } = false;
    public bool ChannelTopNotice { get; set; } = false;
    public bool ChannelSystem { get; set; } = false;
}
