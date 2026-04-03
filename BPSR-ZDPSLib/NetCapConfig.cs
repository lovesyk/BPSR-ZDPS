namespace BPSR_ZDPSLib;

public class NetCapConfig
{
    public string CaptureDeviceName { get; set; } = string.Empty;
    public string[] ExeNames { get; set; } = ["BPSR", "BPSR_STEAM"];
    public TimeSpan ConnectionScanInterval { get; set; } = TimeSpan.FromSeconds(10);

    public bool UseRemoteCapture { get; set; } = false;
    public string RemoteCaptureHost { get; set; } = "192.168.1.100";
    public int RemoteCapturePort { get; set; } = 2002;
    public int RemoteCaptureDeviceIndex { get; set; } = 0;
    public string RemoteCaptureFilter { get; set; } = string.Empty;
}