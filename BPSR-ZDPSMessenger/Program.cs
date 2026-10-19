using BPSR_ZDPSLib;
using BPSR_ZDPSMessenger;
using Microsoft.Extensions.Configuration;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

AppDomain.CurrentDomain.UnhandledException += (_, e) =>
{
    Log.Fatal(e.ExceptionObject as Exception, "Unhandled exception (terminating: {Terminating})", e.IsTerminating);
    Log.CloseAndFlush();
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => Log.Information("Process exiting");
TaskScheduler.UnobservedTaskException += (_, e) => Log.Error(e.Exception, "Unobserved task exception");

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
var notificationHandler = new NotificationHandler(config);

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

NetCap CreateNetCap(Action<string> onLost)
{
    var netCap = new NetCap();
    netCap.Init(netCapConfig);
    netCap.RegisterNotifyHandler(
        (ulong)EServiceId.ChitChatNtf,
        (uint)BPSR_ZDPSLib.ServiceMethods.ChitChatNtf.NotifyNewestChitChatMsgs,
        chatHandler.OnChatMessage);
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
    netCap.CaptureLost += onLost;
    return netCap;
}

Log.Information("Starting BPSR-ZDPSMessenger...");
Log.Information("Running. Press Ctrl+C to stop.");

// A NetCap instance cannot be restarted once stopped, so every (re)connect uses a fresh one.
// Capture loss (rpcapd gone, connection dropped, or traffic stalled) is signalled through this semaphore.
var lostSignal = new SemaphoreSlim(0);
var retryDelay = TimeSpan.FromSeconds(2);
NetCap? current = null;

while (!cts.IsCancellationRequested)
{
    try
    {
        current = CreateNetCap(reason => lostSignal.Release());
        current.Start();
        Log.Information("Capture running");
        retryDelay = TimeSpan.FromSeconds(2);

        await lostSignal.WaitAsync(cts.Token);
        Log.Warning("Capture lost, restarting");
    }
    catch (OperationCanceledException)
    {
        break;
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "Failed to start capture, retrying in {Delay}s", retryDelay.TotalSeconds);
    }

    // Stop may hang or throw on a dead remote connection, so never let it block recovery
    var dead = current;
    current = null;
    if (dead != null)
    {
        try
        {
            // A device that could not be stopped is deliberately left open (leaked) by Stop(), so continuing with a
            // fresh instance is safe; the old handle is never closed while a native thread may still use it.
            if (!Task.Run(dead.Stop).Wait(TimeSpan.FromSeconds(10)))
                Log.Warning("Timed out stopping previous capture, leaking it and continuing");
            else if (dead.StopFailed)
                Log.Warning("Previous capture could not be stopped, leaking it and continuing");
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error stopping previous capture");
        }
    }

    // Drain stale signals (e.g. both the capture-stopped event and the watchdog firing)
    while (lostSignal.Wait(0)) { }

    try
    {
        await Task.Delay(retryDelay, cts.Token);
    }
    catch (OperationCanceledException)
    {
        break;
    }
    retryDelay = TimeSpan.FromSeconds(Math.Min(retryDelay.TotalSeconds * 2, 30));
}

Log.Information("Shutting down...");
current?.Stop();
