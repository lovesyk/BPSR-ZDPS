using BPSR_ZDPSLib;
using BPSR_ZDPSMessenger;
using Microsoft.Extensions.Configuration;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables(prefix: "MESSENGER_")
    .AddCommandLine(args)
    .Build();

var config = configuration.GetSection("Messenger").Get<MessengerConfig>() ?? new MessengerConfig();

var netCapConfig = new NetCapConfig
{
    UseRemoteCapture = true,
    RemoteCaptureHost = config.RemoteCaptureHost,
    RemoteCapturePort = config.RemoteCapturePort,
    RemoteCaptureDeviceIndex = config.RemoteCaptureDeviceIndex,
    RemoteCaptureFilter = config.RemoteCaptureFilter,
};

var chatHandler = new ChatHandler(config);
var netCap = new NetCap();
netCap.Init(netCapConfig);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.ChitChatNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.ChitChatNtf.NotifyNewestChitChatMsgs,
    chatHandler.OnChatMessage);

var notificationHandler = new NotificationHandler(config);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.GrpcTeamNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.GrpcTeamNtf.NotifyInvitation,
    notificationHandler.OnNotifyInvitation);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.GrpcTeamNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.GrpcTeamNtf.NotifyApplyJoin,
    notificationHandler.OnNotifyApplyJoin);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.GrpcTeamNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.GrpcTeamNtf.NotifyRefuseInvite,
    notificationHandler.OnNotifyRefuseInvite);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.GrpcTeamNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.GrpcTeamNtf.NotifyLeaderApplyListSize,
    notificationHandler.OnNotifyLeaderApplyListSize);
netCap.RegisterNotifyHandler(
    (ulong)EServiceId.GrpcTeamNtf,
    (uint)BPSR_ZDPSLib.ServiceMethods.GrpcTeamNtf.NotifyApplyBeLeader,
    notificationHandler.OnNotifyApplyBeLeader);

Log.Information("Starting BPSR-ZDPSMessenger...");
netCap.Start();

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

Log.Information("Running. Press Ctrl+C to stop.");
await Task.Delay(Timeout.Infinite, cts.Token).ContinueWith(_ => { });

Log.Information("Shutting down...");
netCap.Stop();
