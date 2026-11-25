using System.Runtime.InteropServices;
using BPSR_ZDPSLib;
using BPSR_ZDPSRecorder;
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
TaskScheduler.UnobservedTaskException += (_, e) => Log.Error(e.Exception, "Unobserved task exception");

// --regenerate is a plain flag, which the command line configuration provider cannot express
var regenerate = args.Contains("--regenerate");
var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddCommandLine(args.Where(a => a != "--regenerate").ToArray())
    .Build();

var config = configuration.GetSection("Recorder").Get<RecorderConfig>() ?? new RecorderConfig();

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};
using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
{
    ctx.Cancel = true;
    cts.Cancel();
});

using var db = new RecorderDatabase(config.DatabasePath, config.StoreDecodedJson);

if (regenerate)
{
    bool ok;
    try
    {
        ok = await Regenerator.RunAsync(config, db, cts.Token);
    }
    catch (OperationCanceledException)
    {
        Log.Warning("Regeneration cancelled");
        ok = false;
    }

    return ok ? 0 : 1;
}

var netCapConfig = new NetCapConfig
{
    UseRemoteCapture = true,
    RemoteCaptureHost = config.RemoteCaptureHost,
    RemoteCapturePort = config.RemoteCapturePort,
    RemoteCaptureDeviceIndex = config.RemoteCaptureDeviceIndex,
    RemoteCaptureFilter = config.RemoteCaptureFilter,
};

Log.Information("Starting BPSR-ZDPSRecorder, captures go to {CaptureDirectory}, database {DatabasePath}", config.CaptureDirectory, config.DatabasePath);
Log.Information("Running. Press Ctrl+C to stop.");

// A NetCap instance cannot be restarted once stopped, so every (re)connect uses a fresh session (and with it a fresh pcap file).
// Capture loss (rpcapd gone, connection dropped, or traffic stalled) is signalled through this semaphore.
var lostSignal = new SemaphoreSlim(0);
var retryDelay = TimeSpan.FromSeconds(2);
// Finishing a capture (the last pass over the rows added since the previous one) runs in the background so recording resumes right away
var pendingFinishes = new List<Task>();

// Captures a previous run left unfinished (e.g. killed by docker stop) are finished alongside recording
pendingFinishes.Add(Task.Run(async () =>
{
    try
    {
        await db.RecoverUnfinishedCaptures(config.CaptureDirectory, cts.Token);
    }
    catch (OperationCanceledException)
    {
        Log.Warning("Finishing captures left by a previous run was cancelled, it is retried on the next start");
    }
}));

while (!cts.IsCancellationRequested)
{
    var session = new RecordingSession(config, db);
    session.NetCap.CaptureLost += _ => lostSignal.Release();

    try
    {
        session.Start(netCapConfig);
        Log.Information("Capture running");
        retryDelay = TimeSpan.FromSeconds(2);

        await lostSignal.WaitAsync(cts.Token);
        Log.Warning("Capture lost, restarting");
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "Failed to start capture, retrying in {Delay}s", retryDelay.TotalSeconds);
    }

    // Stop may hang or throw on a dead remote connection, so never let it block recovery
    try
    {
        // Give the parser a moment to hand what was already received to the database
        session.NetCap.WaitUntilParsed(TimeSpan.FromSeconds(2));

        // A device that could not be stopped is deliberately left open (leaked) by Stop(), so continuing with a
        // fresh instance is safe; the old handle is never closed while a native thread may still use it.
        if (!Task.Run(session.NetCap.Stop).Wait(TimeSpan.FromSeconds(10)))
            Log.Warning("Timed out stopping previous capture, leaking it and continuing");
        else if (session.NetCap.StopFailed)
            Log.Warning("Previous capture could not be stopped, leaking it and continuing");
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "Error stopping previous capture");
    }

    pendingFinishes.RemoveAll(t => t.IsCompleted);
    pendingFinishes.Add(FinishAsync(session));

    if (cts.IsCancellationRequested)
        break;

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
await Task.WhenAll(pendingFinishes);
return 0;

static async Task FinishAsync(RecordingSession session)
{
    try
    {
        await session.FinishAsync();
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Error finishing the capture");
    }
    session.Dispose();
}
