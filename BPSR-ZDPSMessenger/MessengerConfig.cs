namespace BPSR_ZDPSMessenger;

public class MessengerConfig
{
    public string RemoteCaptureHost { get; set; } = "192.168.1.100";
    public int RemoteCapturePort { get; set; } = 2002;
    public int RemoteCaptureDeviceIndex { get; set; } = 0;
    public string RemoteCaptureFilter { get; set; } = string.Empty;

    public ChannelEndpointConfig ChatEndpoints { get; set; } = new();

    public string[] NotificationEndpoints { get; set; } = [];
}

public class ChannelEndpointConfig
{
    public string[] ChannelNull { get; set; } = [];
    public string[] ChannelWorld { get; set; } = [];
    public string[] ChannelScene { get; set; } = [];
    public string[] ChannelTeam { get; set; } = [];
    public string[] ChannelUnion { get; set; } = [];
    public string[] ChannelPrivate { get; set; } = [];
    public string[] ChannelGroup { get; set; } = [];
    public string[] ChannelTopNotice { get; set; } = [];
    public string[] ChannelSystem { get; set; } = [];
}
