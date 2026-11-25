using System.Collections.Concurrent;
using System.Reflection;
using BPSR_ZDPSLib;
using Microsoft.Data.Sqlite;
using Serilog;

namespace BPSR_ZDPSRecorder;

/// <summary>
/// SQLite store of the recorded game messages. Rows are queued by the parser thread and written in batches by a dedicated thread.
/// </summary>
/// <remarks>
/// Timestamps (<c>ts</c>) are microseconds since the unix epoch (UTC) of the TCP segment that completed the message.
/// Columns that are derived rather than recorded (<c>dir</c>, <c>service</c>, <c>method</c>, <c>reply_to</c>, <c>decoded</c>) and the
/// <c>streams</c> table are computed incrementally: a pass every <see cref="PassInterval"/> while recording handles the rows added since
/// the previous one, finishing only does a last pass over the rest. How far a capture got is stored in <c>captures</c>
/// (<c>streams_upto_id</c>, <c>derived_upto_ts</c>), so a stalled pass shows in the data and an interrupted capture resumes from there.
/// The result does not depend on when the passes ran, so regenerating from the pcap yields the same rows (only <c>streams.id</c> may differ).
/// </remarks>
public sealed class RecorderDatabase : IDisposable
{
    private const int SchemaVersion = 2;

    /// <summary>How often (ms) the derived columns of a capture being recorded are brought up to date.</summary>
    private const long PassInterval = 60_000;

    /// <summary>
    /// A pass only matches the Returns whose <c>ts</c> is at least this much older than the newest row of the capture. Rows are not stored
    /// in <c>ts</c> order: in the recordings up to 2026-11-24 a row came up to 0.25 s (outliers 3.5 s, 9 s, once 34 s) after rows with a
    /// later <c>ts</c>, and 2–14 % of the Calls were stored after their Return. A row arriving behind the cutoff anyway is not lost, the
    /// next pass redoes the Returns from its <c>ts</c> on; the lag only keeps that rare.
    /// </summary>
    private const long DeriveLagMicros = 5 * 60 * 1_000_000L;

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS captures (
            id             INTEGER PRIMARY KEY,
            file           TEXT    NOT NULL UNIQUE, -- pcap file name inside the capture directory
            source         TEXT,                    -- where it was captured (rpcap host / device / filter), kept when regenerating
            parser_version TEXT,                    -- recorder and ZDPSLib build that produced the rows, to spot captures worth regenerating
            started_at     INTEGER,                 -- first packet in the file (us since epoch)
            ended_at       INTEGER,                 -- last packet in the file (us since epoch)
            packet_count   INTEGER,                 -- packets in the pcap
            message_count  INTEGER,                 -- rows in messages
            pcap_bytes     INTEGER,
            parsed_at      INTEGER,                 -- NULL while recording or when the recording was interrupted
            streams_upto_id INTEGER,                -- the capture's rows up to this messages.id are counted in streams / message_count and
                                                    -- have dir where it is known yet
            derived_upto_ts INTEGER                 -- Returns up to this ts have reply_to and the Call's method; trails the newest row by
                                                    -- a few minutes while recording, the last ts once finished
        ) STRICT;

        -- One row per directional tcp stream instance. The parser starts a new instance whenever it loses sync (missing segment,
        -- invalid header, idle timeout), so a stream with continues set may be missing messages before its first one.
        CREATE TABLE IF NOT EXISTS streams (
            id            INTEGER PRIMARY KEY,
            capture_id    INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
            stream        INTEGER NOT NULL,        -- messages.stream
            src_ip        TEXT    NOT NULL,
            src_port      INTEGER NOT NULL,
            dst_ip        TEXT    NOT NULL,
            dst_port      INTEGER NOT NULL,
            dir           TEXT,                    -- 'C2S' / 'S2C'; C2S wins when both occur (the client's unframed ExitGame Notify).
                                                   -- While recording only the direction of its own messages, a stream with only
                                                   -- Echo / counter messages gets the opposite of its reverse stream when finished
            first_ts      INTEGER NOT NULL,
            last_ts       INTEGER NOT NULL,
            message_count INTEGER NOT NULL,
            continues     INTEGER,                 -- the previous stream instance of the same tcp connection (streams.id)
            UNIQUE (capture_id, stream)
        ) STRICT;

        -- Small columns first: a column stored after a large blob can only be read by walking the blob's overflow pages
        CREATE TABLE IF NOT EXISTS messages (
            id            INTEGER PRIMARY KEY,
            capture_id    INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
            ts            INTEGER NOT NULL,        -- us since epoch (UTC)
            stream        INTEGER NOT NULL,        -- id of the directional tcp stream within the capture (streams.stream)
            stream_idx    INTEGER NOT NULL,        -- ordinal of the top level message within its stream
            sub_idx       INTEGER NOT NULL,        -- ordinal within a FrameUp / FrameDown, 0 otherwise
            stream_offset INTEGER NOT NULL,        -- byte offset of the top level message within its stream
            src_ip        TEXT    NOT NULL,
            src_port      INTEGER NOT NULL,
            dst_ip        TEXT    NOT NULL,
            dst_port      INTEGER NOT NULL,
            dir           TEXT,                    -- 'C2S' (client to server) / 'S2C'
            kind          TEXT    NOT NULL,        -- Call, Notify, Return, Echo, UNK1, UNK2, None, FrameUp / FrameDown (only when a frame could not be unpacked)
            container     TEXT,                    -- 'FrameUp' / 'FrameDown' when the message was packed inside one
            frame_id      INTEGER,                 -- FrameUp uuid / FrameDown sequence number
            container_compressed INTEGER NOT NULL, -- the enclosing frame was zstd compressed
            compressed    INTEGER NOT NULL,        -- the message was zstd compressed on the wire (payload is stored decompressed)
            wire_len      INTEGER NOT NULL,        -- length field of the message header (header included, compressed); within the frame for packed messages
            service_id    INTEGER,
            service       TEXT,                    -- name known to ZDPSLib, NULL when unknown
            method_id     INTEGER,
            method        TEXT,
            stub_id       INTEGER,                 -- Notify stub id / sub id of Call and Return
            return_uid    INTEGER,                 -- ties a Return to its Call
            reply_to      INTEGER,                 -- for Return: the Call it answers (messages.id, always within the same capture)
            aux           INTEGER,                 -- third header field of a Return (meaning unknown)
            error         TEXT,                    -- 'decompress' / 'truncated' (too short for its header, kind is the expected one or None)
            payload_len   INTEGER NOT NULL,
            payload       BLOB    NOT NULL,        -- decompressed protobuf (or the raw bytes when error is set)
            decoded       TEXT                     -- payload as JSON when ZDPSLib knows the protobuf type
        ) STRICT;

        CREATE INDEX IF NOT EXISTS idx_messages_capture_ts  ON messages(capture_id, ts);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_stream ON messages(capture_id, stream, stream_idx, sub_idx);
        CREATE INDEX IF NOT EXISTS idx_messages_method      ON messages(service_id, method_id, kind);
        CREATE INDEX IF NOT EXISTS idx_messages_return_uid  ON messages(capture_id, return_uid) WHERE return_uid IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_messages_reply_to    ON messages(reply_to) WHERE reply_to IS NOT NULL;
        -- Lets a pass find the Call a Return answers directly; without it every Return walks back through the whole capture
        CREATE INDEX IF NOT EXISTS idx_messages_calls       ON messages(capture_id, return_uid, ts) WHERE kind = 'Call';
        -- Lets a pass find the messages without a direction (Echo, counters) directly; passes set dir, so it stays small
        CREATE INDEX IF NOT EXISTS idx_messages_nodir       ON messages(capture_id, stream) WHERE dir IS NULL;
        """;

    private abstract record WorkItem;
    private sealed record BeginItem(CaptureHandle Capture) : WorkItem;
    private sealed record MessageItem(CaptureHandle Capture, GameMessageInfo Info, byte[] Payload) : WorkItem;
    private sealed record FinishItem(CaptureHandle Capture, long? StartedAt, long? EndedAt, long? PacketCount, long? PcapBytes, TaskCompletionSource Done) : WorkItem;

    /// <summary>A capture registered with <see cref="BeginCapture"/>. Its row is created by the writer thread, in queue order.</summary>
    public sealed class CaptureHandle(string file, string? source)
    {
        public string File { get; } = file;
        public string? Source { get; } = source;
        /// <summary>Row id, only set (and only read) on the writer thread.</summary>
        internal long Id;
        /// <summary>Registering failed, the messages of this capture are skipped instead of each failing on its own.</summary>
        internal bool Failed;
        /// <summary><see cref="Environment.TickCount64"/> at which the next pass is due. Writer thread only.</summary>
        internal long NextPass;
    }

    private static readonly string ParserVersion =
        $"Recorder {VersionOf(typeof(RecorderDatabase).Assembly)}, ZDPSLib {VersionOf(typeof(NetCap).Assembly)}";

    private readonly SqliteConnection _connection;
    private readonly BlockingCollection<WorkItem> _queue = new(100_000);
    private readonly Thread _writer;
    private readonly NameResolver _resolver = new();
    private readonly bool _storeDecoded;
    private SqliteCommand? _insert;
    private int _queueFullLogged;
    private readonly List<CaptureHandle> _unfinishedAtOpen = new();
    /// <summary>Captures registered and not finished yet, the ones passes run for. Writer thread only.</summary>
    private readonly HashSet<CaptureHandle> _recording = new();

    public RecorderDatabase(string path, bool storeDecoded)
    {
        _storeDecoded = storeDecoded;

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        _connection = new SqliteConnection($"Data Source={path};Pooling=False");
        _connection.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;");
        // Truncate the WAL file back to this size after a checkpoint; it otherwise stays as large as the largest transaction ever made it
        Execute("PRAGMA journal_size_limit=67108864;");

        var version = Convert.ToInt32(Scalar("PRAGMA user_version;"));
        if (version > SchemaVersion)
            throw new InvalidOperationException($"{path} has schema version {version}, newer than this recorder supports ({SchemaVersion})");

        if (Scalar("SELECT 1 FROM sqlite_master WHERE name = 'messages'") != null)
        {
            foreach (var index in new[] { "idx_messages_calls", "idx_messages_nodir" })
            {
                if (Scalar($"SELECT 1 FROM sqlite_master WHERE name = '{index}'") == null)
                    Log.Information("Adding index {Index}, this reads the whole database once and can take a few minutes", index);
            }
        }
        Execute(Schema);
        // Schema version 1 databases: the pass watermarks (NULL for their captures; an unfinished one is then finished from its first row)
        foreach (var column in new[] { "streams_upto_id", "derived_upto_ts" })
        {
            if (Scalar($"SELECT 1 FROM pragma_table_info('captures') WHERE name = '{column}'") == null)
                Execute($"ALTER TABLE captures ADD COLUMN {column} INTEGER;");
        }
        Execute($"PRAGMA user_version={SchemaVersion};");

        // Captures a previous run did not finish (killed while recording or finishing). Read before the writer starts, so captures of this run are never included.
        using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id, file, source FROM captures WHERE parsed_at IS NULL ORDER BY id";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                _unfinishedAtOpen.Add(new CaptureHandle(reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2)) { Id = reader.GetInt64(0) });
        }

        _writer = new Thread(WriterLoop) { Name = "RecorderDb", IsBackground = false };
        _writer.Start();
    }

    /// <summary>
    /// Registers a capture file. Rows of a previous run for the same file are removed (regeneration overwrites), its
    /// <paramref name="source"/> is kept when none is given.
    /// Does not touch the database itself, so it never blocks the caller on a long running write (e.g. finishing the previous capture).
    /// </summary>
    public CaptureHandle BeginCapture(string file, string? source = null)
    {
        var capture = new CaptureHandle(file, source);
        Add(new BeginItem(capture));
        return capture;
    }

    public void Enqueue(CaptureHandle capture, GameMessageInfo info, ReadOnlySpan<byte> payload)
    {
        Add(new MessageItem(capture, info, payload.ToArray()));
    }

    /// <summary>Completes once every message queued before this call was stored and the derived columns were computed; faults when finishing failed.</summary>
    public Task EndCapture(CaptureHandle capture, DateTime? firstPacketTime, DateTime? lastPacketTime, long? packetCount, long? pcapBytes)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Add(new FinishItem(capture, firstPacketTime == null ? null : ToMicros(firstPacketTime.Value),
            lastPacketTime == null ? null : ToMicros(lastPacketTime.Value), packetCount, pcapBytes, done));
        return done.Task;
    }

    /// <summary>
    /// Finishes the captures a previous run left unfinished (<c>parsed_at</c> NULL when the database was opened). Their message rows are
    /// complete up to the moment the recorder died, only the derived columns are missing. Packet statistics are read back from the pcap
    /// when it still exists, otherwise the time range is taken from the messages.
    /// </summary>
    public async Task RecoverUnfinishedCaptures(string captureDirectory, CancellationToken cancellationToken)
    {
        foreach (var capture in _unfinishedAtOpen)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Log.Information("Finishing capture {File} left unfinished by a previous run", capture.File);

            DateTime? first = null, last = null;
            long? packets = null, bytes = null;
            var path = Path.Combine(captureDirectory, capture.File);
            try
            {
                if (File.Exists(path))
                {
                    long count = 0;
                    using var pcap = new PcapFileReader(path);
                    foreach (var packet in pcap.ReadPackets())
                    {
                        if ((++count & 0xFFFF) == 0)
                            cancellationToken.ThrowIfCancellationRequested();
                        first ??= packet.Timeval.Date;
                        last = packet.Timeval.Date;
                    }
                    packets = count;
                    bytes = new FileInfo(path).Length;
                }
                else
                {
                    Log.Warning("{Path} no longer exists, finishing {File} without packet statistics", path, capture.File);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.Warning(ex, "Could not read {Path}, finishing {File} without packet statistics", path, capture.File);
                first = last = null;
                packets = bytes = null;
            }

            try
            {
                await EndCapture(capture, first, last, packets, bytes);
                Log.Information("Finished {File} left by a previous run", capture.File);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Finishing {File} left by a previous run failed", capture.File);
            }
        }
        _unfinishedAtOpen.Clear();
    }

    private void Add(WorkItem item)
    {
        if (_queue.TryAdd(item))
            return;

        // The writer can't keep up; this blocks the caller (and with it the parser) until there is room again
        if (Interlocked.Exchange(ref _queueFullLogged, 1) == 0)
            Log.Warning("Database write queue is full ({Count} items), the parser is waiting on the database", _queue.BoundedCapacity);
        _queue.Add(item);
    }

    private void WriterLoop()
    {
        var batch = new List<WorkItem>();
        while (!_queue.IsCompleted)
        {
            if (_queue.TryTake(out var item, 250))
            {
                batch.Clear();
                do
                {
                    batch.Add(item);
                } while (batch.Count < 2000 && _queue.TryTake(out item!));
                WriteBatch(batch);
            }
            else
            {
                Volatile.Write(ref _queueFullLogged, 0);
            }

            RunDuePasses();
        }
    }

    private void WriteBatch(List<WorkItem> batch)
    {
        try
        {
            using var tx = _connection.BeginTransaction();
            foreach (var batchItem in batch)
                Process(batchItem, tx);
            tx.Commit();
        }
        catch (Exception ex)
        {
            // The transaction was rolled back; redo the batch item by item so only what actually fails is lost
            Log.Warning(ex, "Writing a batch of {Count} items failed, retrying them one by one", batch.Count);
            foreach (var batchItem in batch)
                ProcessAlone(batchItem);
            return;
        }

        foreach (var batchItem in batch)
        {
            if (batchItem is FinishItem finish)
                finish.Done.TrySetResult();
        }
    }

    /// <summary>Brings the derived columns of the captures being recorded up to date, each in its own transaction.</summary>
    private void RunDuePasses()
    {
        var now = Environment.TickCount64;
        foreach (var capture in _recording)
        {
            if (capture.Failed || now < capture.NextPass)
                continue;
            capture.NextPass = now + PassInterval;
            try
            {
                using var tx = _connection.BeginTransaction();
                Derive(capture.Id, final: false, tx);
                tx.Commit();
            }
            catch (Exception ex)
            {
                // Nothing is lost: the next pass (or finishing) starts from the watermarks of the last successful one
                Log.Warning(ex, "Updating the derived columns of {File} failed", capture.File);
            }
        }
    }

    private void ProcessAlone(WorkItem item)
    {
        try
        {
            using var tx = _connection.BeginTransaction();
            Process(item, tx);
            tx.Commit();
            if (item is FinishItem finish)
                finish.Done.TrySetResult();
        }
        catch (Exception ex)
        {
            switch (item)
            {
                case BeginItem begin:
                    begin.Capture.Failed = true;
                    _recording.Remove(begin.Capture);
                    Log.Error(ex, "Registering capture {File} failed, its messages are not stored", begin.Capture.File);
                    break;
                case MessageItem message:
                    Log.Error(ex, "Storing a {Kind} message of {File} failed, it was dropped", message.Info.Kind, message.Capture.File);
                    break;
                case FinishItem finish:
                    Log.Error(ex, "Finishing capture {File} failed", finish.Capture.File);
                    finish.Done.TrySetException(ex);
                    break;
            }
        }
    }

    private void Process(WorkItem item, SqliteTransaction tx)
    {
        switch (item)
        {
            case BeginItem begin:
                RegisterCapture(begin.Capture, tx);
                break;
            case MessageItem message:
                if (!message.Capture.Failed)
                    InsertMessage(message, tx);
                break;
            case FinishItem finish:
                if (finish.Capture.Failed)
                    throw new InvalidOperationException($"Capture {finish.Capture.File} was never registered");
                FinishCapture(finish, tx);
                break;
        }
    }

    private void RegisterCapture(CaptureHandle capture, SqliteTransaction tx)
    {
        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO captures(file, source, parser_version) VALUES($file, $source, $version)
                ON CONFLICT(file) DO UPDATE SET source = COALESCE(excluded.source, source), parser_version = excluded.parser_version,
                    started_at = NULL, ended_at = NULL, packet_count = NULL, message_count = NULL, pcap_bytes = NULL, parsed_at = NULL,
                streams_upto_id = NULL, derived_upto_ts = NULL
                RETURNING id;
                """;
            cmd.Parameters.AddWithValue("$file", capture.File);
            cmd.Parameters.AddWithValue("$source", (object?)capture.Source ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$version", ParserVersion);
            capture.Id = (long)cmd.ExecuteScalar()!;
        }

        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            // Every row of this capture is inserted after this, so its ids are above the current largest one
            cmd.CommandText = """
                DELETE FROM messages WHERE capture_id = $id; DELETE FROM streams WHERE capture_id = $id;
                UPDATE captures SET streams_upto_id = (SELECT IFNULL(MAX(id), 0) FROM messages) WHERE id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", capture.Id);
            cmd.ExecuteNonQuery();
        }

        capture.NextPass = Environment.TickCount64 + PassInterval;
        _recording.Add(capture);
    }

    private void InsertMessage(MessageItem item, SqliteTransaction tx)
    {
        var info = item.Info;
        var payload = item.Payload;

        var dir = DirectionOf(info);
        var serverNotify = info.Kind == MsgTypeId.Notify && info.Container != MessageContainer.FrameUp;
        var (service, method) = _resolver.Resolve(info.ServiceId, info.MethodId, serverNotify);
        var decoded = _storeDecoded && !info.DecompressFailed && !info.Truncated ? _resolver.TryDecode(service, method, info.Kind, payload) : null;

        if (_insert == null)
        {
            _insert = _connection.CreateCommand();
            _insert.CommandText = """
                INSERT INTO messages (capture_id, ts, stream, stream_idx, sub_idx, stream_offset, src_ip, src_port, dst_ip, dst_port, dir, kind, container,
                                      frame_id, container_compressed, compressed, wire_len, service_id, service, method_id, method, stub_id, return_uid, aux,
                                      error, payload_len, payload, decoded)
                VALUES ($capture, $ts, $stream, $streamIdx, $subIdx, $streamOffset, $srcIp, $srcPort, $dstIp, $dstPort, $dir, $kind, $container,
                        $frameId, $containerCompressed, $compressed, $wireLen, $serviceId, $service, $methodId, $method, $stubId, $returnUid, $aux,
                        $error, $payloadLen, $payload, $decoded);
                """;
            foreach (var name in new[] { "$capture", "$ts", "$stream", "$streamIdx", "$subIdx", "$streamOffset", "$srcIp", "$srcPort", "$dstIp", "$dstPort",
                         "$dir", "$kind", "$container", "$frameId", "$containerCompressed", "$compressed", "$wireLen", "$serviceId", "$service", "$methodId",
                         "$method", "$stubId", "$returnUid", "$aux", "$error", "$payloadLen", "$payload", "$decoded" })
            {
                _insert.Parameters.Add(new SqliteParameter { ParameterName = name });
            }
        }

        _insert.Transaction = tx;
        var p = _insert.Parameters;
        p["$capture"].Value = item.Capture.Id;
        p["$ts"].Value = ToMicros(info.Time);
        p["$stream"].Value = info.StreamId;
        p["$streamIdx"].Value = info.StreamIndex;
        p["$subIdx"].Value = info.SubIndex;
        p["$streamOffset"].Value = info.StreamOffset;
        p["$srcIp"].Value = info.Source?.Address.ToString() ?? "";
        p["$srcPort"].Value = info.Source?.Port ?? 0;
        p["$dstIp"].Value = info.Destination?.Address.ToString() ?? "";
        p["$dstPort"].Value = info.Destination?.Port ?? 0;
        p["$dir"].Value = (object?)dir ?? DBNull.Value;
        p["$kind"].Value = Enum.IsDefined(info.Kind) ? info.Kind.ToString() : $"Type{(int)info.Kind}";
        p["$container"].Value = info.Container == MessageContainer.None ? DBNull.Value : info.Container.ToString();
        p["$frameId"].Value = (object?)info.FrameId ?? DBNull.Value;
        p["$containerCompressed"].Value = info.ContainerCompressed ? 1 : 0;
        p["$compressed"].Value = info.Compressed ? 1 : 0;
        p["$wireLen"].Value = info.WireLength;
        p["$serviceId"].Value = info.ServiceId == null ? DBNull.Value : unchecked((long)info.ServiceId.Value);
        p["$service"].Value = (object?)service ?? DBNull.Value;
        p["$methodId"].Value = (object?)info.MethodId ?? DBNull.Value;
        p["$method"].Value = (object?)method ?? DBNull.Value;
        p["$stubId"].Value = (object?)info.StubId ?? DBNull.Value;
        p["$returnUid"].Value = (object?)info.ReturnUid ?? DBNull.Value;
        p["$aux"].Value = (object?)info.Aux ?? DBNull.Value;
        p["$payloadLen"].Value = payload.Length;
        p["$payload"].Value = payload;
        p["$decoded"].Value = (object?)decoded ?? DBNull.Value;
        p["$error"].Value = info.DecompressFailed ? "decompress" : info.Truncated ? "truncated" : DBNull.Value;
        _insert.ExecuteNonQuery();
    }

    private static string? DirectionOf(GameMessageInfo info)
    {
        if (info.Container == MessageContainer.FrameUp)
            return "C2S";
        if (info.Container == MessageContainer.FrameDown)
            return "S2C";

        return info.Kind switch
        {
            MsgTypeId.Call => "C2S",
            MsgTypeId.Notify or MsgTypeId.Return => "S2C",
            _ => null,
        };
    }

    /// <summary>Does the last pass over the rows the passes while recording did not cover yet and records the packet statistics.</summary>
    private void FinishCapture(FinishItem finish, SqliteTransaction tx)
    {
        _recording.Remove(finish.Capture);
        Derive(finish.Capture.Id, final: true, tx);

        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE captures SET
                started_at = COALESCE($start, (SELECT MIN(ts) FROM messages WHERE capture_id = $c)),
                ended_at = COALESCE($end, (SELECT MAX(ts) FROM messages WHERE capture_id = $c)),
                packet_count = $packets, pcap_bytes = $bytes, parsed_at = $now
            WHERE id = $c;
            """;
        cmd.Parameters.AddWithValue("$c", finish.Capture.Id);
        cmd.Parameters.AddWithValue("$start", (object?)finish.StartedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$end", (object?)finish.EndedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$packets", (object?)finish.PacketCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$bytes", (object?)finish.PcapBytes ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$now", ToMicros(DateTime.UtcNow));
        cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// One pass: computes the columns that depend on other rows of the capture, for the rows added since the previous pass (read from
    /// the watermarks in <c>captures</c>, which are updated in the same transaction, so a failed or interrupted pass is simply redone).
    /// The result does not depend on how the rows were split into passes. <paramref name="final"/> covers every row and completes
    /// <c>streams.dir</c>; no row may be added after it.
    /// </summary>
    private void Derive(long captureId, bool final, SqliteTransaction tx)
    {
        SqliteCommand Command(string sql, params (string Name, object? Value)[] parameters)
        {
            var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.Parameters.AddWithValue("$c", captureId);
            foreach (var (name, value) in parameters)
                cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
            return cmd;
        }
        void Run(string sql, params (string, object?)[] parameters)
        {
            using var cmd = Command(sql, parameters);
            cmd.ExecuteNonQuery();
        }
        long? Long(string sql, params (string, object?)[] parameters)
        {
            using var cmd = Command(sql, parameters);
            return cmd.ExecuteScalar() is long value ? value : null;
        }

        // The capture's rows above streams_upto_id are the new ones. A capture registered by a schema version 1 recorder has no
        // watermarks; it was never finished (so has no streams rows), all of its rows are new.
        long? streamsUpto = null, derivedUpto = null;
        using (var cmd = Command("SELECT streams_upto_id, derived_upto_ts FROM captures WHERE id = $c"))
        using (var reader = cmd.ExecuteReader())
        {
            if (!reader.Read())
                throw new InvalidOperationException($"Capture {captureId} does not exist");
            streamsUpto = reader.IsDBNull(0) ? null : reader.GetInt64(0);
            derivedUpto = reader.IsDBNull(1) ? null : reader.GetInt64(1);
        }
        var fromId = streamsUpto
            ?? Long("SELECT IFNULL(MIN(id) - 1, (SELECT IFNULL(MAX(id), 0) FROM messages)) FROM messages WHERE capture_id = $c")!.Value;
        var toId = Long("SELECT IFNULL(MAX(id), 0) FROM messages")!.Value;
        // The new rows are read by id range (NOT INDEXED: the rowid, not the capture's index, which would read the whole capture)
        const string NewRows = "messages NOT INDEXED WHERE id > $fromId AND id <= $toId AND capture_id = $c";
        (string, object?) FromId = ("$fromId", fromId), ToId = ("$toId", toId);

        // A new row at or before the previous cutoff arrived later than the lag allows for; the Returns from its ts on are redone below
        var lateTs = derivedUpto == null ? null : Long($"SELECT MIN(ts) FROM {NewRows} AND ts <= $derived", FromId, ToId, ("$derived", derivedUpto));

        // Streams: add the new rows to the totals. dir is the direction of the stream's own messages, C2S winning over S2C (a client
        // stream ends with the client's unframed ExitGame Notify, which DirectionOf takes for S2C)
        var before = StreamDirections(captureId, tx);
        Run($"""
            INSERT INTO streams (capture_id, stream, src_ip, src_port, dst_ip, dst_port, dir, first_ts, last_ts, message_count)
            SELECT capture_id, stream, src_ip, src_port, dst_ip, dst_port, MIN(dir), MIN(ts), MAX(ts), COUNT(*)
            FROM {NewRows} GROUP BY stream
            ON CONFLICT (capture_id, stream) DO UPDATE SET
                dir = COALESCE(MIN(dir, excluded.dir), dir, excluded.dir), first_ts = MIN(first_ts, excluded.first_ts),
                last_ts = MAX(last_ts, excluded.last_ts), message_count = message_count + excluded.message_count;
            """, FromId, ToId);
        var after = StreamDirections(captureId, tx);

        // Stream ids are assigned in packet order, so the latest lower id on the same endpoints is the instance this one replaced
        Run("""
            UPDATE streams SET continues = (
                SELECT p.id FROM streams p
                WHERE p.capture_id = streams.capture_id AND p.stream < streams.stream
                  AND p.src_ip = streams.src_ip AND p.src_port = streams.src_port AND p.dst_ip = streams.dst_ip AND p.dst_port = streams.dst_port
                ORDER BY p.stream DESC LIMIT 1)
            WHERE capture_id = $c;
            """);

        // Messages without a direction of their own (Echo, counters) take their stream's. A stream whose direction changed since an
        // earlier pass (C2S arriving after S2C, or the reverse stream deciding it) gets its already filled ones corrected.
        foreach (var (stream, dir) in after)
        {
            if (before.TryGetValue(stream, out var old) && old != null && old != dir)
            {
                Run("""
                    UPDATE messages INDEXED BY idx_messages_stream SET dir = $dir
                    WHERE capture_id = $c AND stream = $s AND dir = $old AND container IS NULL AND kind NOT IN ('Call', 'Notify', 'Return');
                    """, ("$s", stream), ("$dir", dir), ("$old", old));
            }
        }
        var undirected = new List<long>();
        using (var cmd = Command("SELECT DISTINCT stream FROM messages INDEXED BY idx_messages_nodir WHERE capture_id = $c AND dir IS NULL"))
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
                undirected.Add(reader.GetInt64(0));
        }
        foreach (var stream in undirected)
        {
            if (after.TryGetValue(stream, out var dir) && dir != null)
                Run("UPDATE messages INDEXED BY idx_messages_nodir SET dir = $dir WHERE capture_id = $c AND stream = $s AND dir IS NULL;", ("$s", stream), ("$dir", dir));
        }
        if (final)
        {
            foreach (var (stream, dir) in after)
            {
                if (dir != null)
                    Run("UPDATE streams SET dir = $dir WHERE capture_id = $c AND stream = $s AND dir IS NULL;", ("$s", stream), ("$dir", dir));
            }
        }

        // Returns: only up to the cutoff, so their Calls (stored up to a few seconds late) are there
        var newestTs = Long("SELECT MAX(ts) FROM messages WHERE capture_id = $c");
        var cutoff = final ? newestTs : newestTs - DeriveLagMicros;
        var fromTs = derivedUpto ?? long.MinValue;
        if (lateTs != null)
            fromTs = Math.Min(fromTs, lateTs.Value - 1);
        if (cutoff != null && cutoff > fromTs)
        {
            (string, object?) From = ("$fromTs", fromTs), To = ("$toTs", cutoff);
            const string Range = "messages.capture_id = $c AND messages.ts > $fromTs AND messages.ts <= $toTs";

            // A Return answers the latest preceding Call with the same return uid on the opposite direction of the same connection
            Run($"""
                UPDATE messages INDEXED BY idx_messages_capture_ts SET reply_to = (
                    SELECT c.id FROM messages c INDEXED BY idx_messages_calls
                    WHERE c.capture_id = messages.capture_id AND c.kind = 'Call' AND c.return_uid = messages.return_uid
                      AND c.src_ip = messages.dst_ip AND c.src_port = messages.dst_port AND c.dst_ip = messages.src_ip AND c.dst_port = messages.src_port
                      AND c.ts <= messages.ts
                    ORDER BY c.ts DESC, c.id DESC LIMIT 1)
                WHERE {Range} AND messages.kind = 'Return' AND messages.return_uid IS NOT NULL;
                """, From, To);

            // The Return itself does not say which method it belongs to, that is the Call's. ZDPSLib's own guess (the latest Call with that
            // return uid on any connection) is only kept when no Call was matched; a corrected Return is decoded again below.
            Run($"""
                UPDATE messages INDEXED BY idx_messages_capture_ts
                SET service_id = c.service_id, service = c.service, method_id = c.method_id, method = c.method, decoded = NULL
                FROM messages c
                WHERE {Range} AND messages.kind = 'Return' AND messages.return_uid IS NOT NULL AND c.id = messages.reply_to
                  AND (messages.service_id IS NOT c.service_id OR messages.method_id IS NOT c.method_id);
                """, From, To);

            if (_storeDecoded)
                DecodeReturns(captureId, fromTs, cutoff.Value, tx);

            derivedUpto = derivedUpto == null ? cutoff : Math.Max(derivedUpto.Value, cutoff.Value);
        }

        Run("""
            UPDATE captures SET streams_upto_id = $toId, derived_upto_ts = $derived,
                message_count = (SELECT IFNULL(SUM(message_count), 0) FROM streams WHERE capture_id = $c)
            WHERE id = $c;
            """, ToId, ("$derived", derivedUpto));
    }

    /// <summary>
    /// The direction of each stream of the capture: its own (<c>streams.dir</c>), else the opposite of its reverse stream's own one
    /// (the lowest stream number with one); null while neither is known.
    /// </summary>
    private Dictionary<long, string?> StreamDirections(long captureId, SqliteTransaction tx)
    {
        var streams = new List<(long Stream, string Src, string Dst, string? Dir)>();
        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT stream, src_ip, src_port, dst_ip, dst_port, dir FROM streams WHERE capture_id = $c ORDER BY stream";
            cmd.Parameters.AddWithValue("$c", captureId);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                streams.Add((reader.GetInt64(0), $"{reader.GetString(1)}:{reader.GetInt64(2)}", $"{reader.GetString(3)}:{reader.GetInt64(4)}",
                    reader.IsDBNull(5) ? null : reader.GetString(5)));
            }
        }

        var ownByEndpoints = new Dictionary<(string Src, string Dst), string>();
        foreach (var s in streams)
        {
            if (s.Dir != null)
                ownByEndpoints.TryAdd((s.Src, s.Dst), s.Dir);
        }

        var result = new Dictionary<long, string?>();
        foreach (var s in streams)
        {
            result[s.Stream] = s.Dir ?? (ownByEndpoints.TryGetValue((s.Dst, s.Src), out var reverse) ? (reverse == "C2S" ? "S2C" : "C2S") : null);
        }
        return result;
    }

    /// <summary>
    /// Decodes the Returns in the ts range whose method a pass corrected (<c>decoded</c> cleared above). Only Returns with a return uid
    /// can be corrected; any other Return without <c>decoded</c> already failed to decode with the same method on insert.
    /// </summary>
    private void DecodeReturns(long captureId, long fromTs, long toTs, SqliteTransaction tx)
    {
        var updates = new List<(long Id, string Json)>();
        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                SELECT id, service, method, payload FROM messages INDEXED BY idx_messages_capture_ts
                WHERE capture_id = $c AND ts > $fromTs AND ts <= $toTs
                  AND kind = 'Return' AND return_uid IS NOT NULL AND decoded IS NULL AND method IS NOT NULL AND error IS NULL AND payload_len > 0;
                """;
            cmd.Parameters.AddWithValue("$c", captureId);
            cmd.Parameters.AddWithValue("$fromTs", fromTs);
            cmd.Parameters.AddWithValue("$toTs", toTs);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var payload = (byte[])reader["payload"];
                var json = _resolver.TryDecode(reader.GetString(1), reader.GetString(2), MsgTypeId.Return, payload);
                if (json != null)
                    updates.Add((reader.GetInt64(0), json));
            }
        }

        foreach (var (id, json) in updates)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "UPDATE messages SET decoded = $json WHERE id = $id";
            cmd.Parameters.AddWithValue("$json", json);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    private static string VersionOf(Assembly assembly) =>
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? assembly.GetName().Version?.ToString() ?? "unknown";

    public static long ToMicros(DateTime time)
    {
        // Capture timestamps are UTC; Unspecified is treated as UTC as well
        var utc = time.Kind == DateTimeKind.Local ? time.ToUniversalTime() : time;
        return (utc.Ticks - DateTime.UnixEpoch.Ticks) / 10;
    }

    private void Execute(string sql)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private object? Scalar(string sql)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }

    /// <summary>Writes everything that is still queued, then closes the database.</summary>
    public void Dispose()
    {
        _queue.CompleteAdding();
        _writer.Join();
        _insert?.Dispose();
        _connection.Dispose();
    }
}
