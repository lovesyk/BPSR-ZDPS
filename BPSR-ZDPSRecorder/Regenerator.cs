using BPSR_ZDPSLib;
using Serilog;

namespace BPSR_ZDPSRecorder;

/// <summary>Rebuilds the database rows from the pcap files that already exist, replacing the rows of a capture that is already in the database.</summary>
public static class Regenerator
{
    public static async Task<bool> RunAsync(RecorderConfig config, RecorderDatabase db, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(config.CaptureDirectory))
        {
            Log.Error("Capture directory {Directory} does not exist", config.CaptureDirectory);
            return false;
        }

        var files = Directory.EnumerateFiles(config.CaptureDirectory, "*.pcap").Order(StringComparer.Ordinal).ToList();
        Log.Information("Regenerating {Count} capture(s) from {Directory}", files.Count, config.CaptureDirectory);

        var allSucceeded = true;
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var name = Path.GetFileName(file);
            // The replay runs on a copy whose stream starts are re-cut, so first messages are kept (see PcapStreamStart)
            var recutPath = Path.Combine(Path.GetTempPath(), $"zdps-regenerate-{Guid.NewGuid():N}.pcap");
            try
            {
                var recut = PcapStreamStart.Rewrite(file, recutPath);
                var capture = db.BeginCapture(name);
                var netCap = new NetCap();
                var messages = 0L;
                netCap.MessageReceived += (info, payload) =>
                {
                    db.Enqueue(capture, info, payload);
                    messages++;
                };

                var stats = netCap.ReplayFile(recutPath, cancellationToken);
                await db.EndCapture(capture, stats.FirstPacketTime, stats.LastPacketTime, recut.PacketCount, new FileInfo(file).Length);
                Log.Information("{File}: {Packets} packets, {Messages} messages, {Recut} stream start(s) re-cut",
                    name, recut.PacketCount, messages, recut.StreamsRecut);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                allSucceeded = false;
                Log.Error(ex, "Regenerating {File} failed", name);
            }
            finally
            {
                try { File.Delete(recutPath); } catch (Exception) { }
            }
        }

        return allSucceeded;
    }
}
