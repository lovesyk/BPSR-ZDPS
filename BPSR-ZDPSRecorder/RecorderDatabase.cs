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
/// <c>streams</c> table are (re)computed when the capture is finished, so regenerating from the pcap always yields the same rows.
/// </remarks>
public sealed class RecorderDatabase : IDisposable
{
    private const int SchemaVersion = 1;

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
            parsed_at      INTEGER                  -- NULL while recording or when the recording was interrupted
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
            dir           TEXT,                    -- 'C2S' / 'S2C'
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
        """;

    private abstract record WorkItem;
    private sealed record BeginItem(CaptureHandle Capture) : WorkItem;
    private sealed record MessageItem(CaptureHandle Capture, GameMessageInfo Info, byte[] Payload) : WorkItem;
    private sealed record FinishItem(CaptureHandle Capture, long? StartedAt, long? EndedAt, long PacketCount, long PcapBytes, TaskCompletionSource Done) : WorkItem;

    /// <summary>A capture registered with <see cref="BeginCapture"/>. Its row is created by the writer thread, in queue order.</summary>
    public sealed class CaptureHandle(string file, string? source)
    {
        public string File { get; } = file;
        public string? Source { get; } = source;
        /// <summary>Row id, only set (and only read) on the writer thread.</summary>
        internal long Id;
        /// <summary>Registering failed, the messages of this capture are skipped instead of each failing on its own.</summary>
        internal bool Failed;
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

    public RecorderDatabase(string path, bool storeDecoded)
    {
        _storeDecoded = storeDecoded;

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        _connection = new SqliteConnection($"Data Source={path};Pooling=False");
        _connection.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;");

        var version = Convert.ToInt32(Scalar("PRAGMA user_version;"));
        if (version > SchemaVersion)
            throw new InvalidOperationException($"{path} has schema version {version}, newer than this recorder supports ({SchemaVersion})");

        Execute(Schema);
        Execute($"PRAGMA user_version={SchemaVersion};");

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
    public Task EndCapture(CaptureHandle capture, DateTime? firstPacketTime, DateTime? lastPacketTime, long packetCount, long pcapBytes)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Add(new FinishItem(capture, firstPacketTime == null ? null : ToMicros(firstPacketTime.Value),
            lastPacketTime == null ? null : ToMicros(lastPacketTime.Value), packetCount, pcapBytes, done));
        return done.Task;
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
            if (!_queue.TryTake(out var item, 250))
            {
                Volatile.Write(ref _queueFullLogged, 0);
                continue;
            }

            batch.Clear();
            do
            {
                batch.Add(item);
            } while (batch.Count < 2000 && _queue.TryTake(out item!));

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
                continue;
            }

            foreach (var batchItem in batch)
            {
                if (batchItem is FinishItem finish)
                    finish.Done.TrySetResult();
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
                    started_at = NULL, ended_at = NULL, packet_count = NULL, message_count = NULL, pcap_bytes = NULL, parsed_at = NULL
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
            cmd.CommandText = "DELETE FROM messages WHERE capture_id = $id; DELETE FROM streams WHERE capture_id = $id;";
            cmd.Parameters.AddWithValue("$id", capture.Id);
            cmd.ExecuteNonQuery();
        }
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

    /// <summary>Computes the columns that can only be known once the whole capture is available, independent of the order messages were parsed in.</summary>
    private void FinishCapture(FinishItem finish, SqliteTransaction tx)
    {
        void Run(string sql)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.Parameters.AddWithValue("$c", finish.Capture.Id);
            cmd.ExecuteNonQuery();
        }

        Run("""
            INSERT INTO streams (capture_id, stream, src_ip, src_port, dst_ip, dst_port, dir, first_ts, last_ts, message_count)
            SELECT capture_id, stream, src_ip, src_port, dst_ip, dst_port, MAX(dir), MIN(ts), MAX(ts), COUNT(*)
            FROM messages WHERE capture_id = $c GROUP BY stream;
            """);

        // A stream with only Echo / counter messages has the opposite direction of the other half of its connection
        Run("""
            UPDATE streams SET dir = (
                SELECT CASE o.dir WHEN 'C2S' THEN 'S2C' ELSE 'C2S' END FROM streams o
                WHERE o.capture_id = streams.capture_id AND o.dir IS NOT NULL
                  AND o.src_ip = streams.dst_ip AND o.src_port = streams.dst_port AND o.dst_ip = streams.src_ip AND o.dst_port = streams.src_port
                LIMIT 1)
            WHERE capture_id = $c AND dir IS NULL;
            """);

        // Stream ids are assigned in packet order, so the latest lower id on the same endpoints is the instance this one replaced
        Run("""
            UPDATE streams SET continues = (
                SELECT p.id FROM streams p
                WHERE p.capture_id = streams.capture_id AND p.stream < streams.stream
                  AND p.src_ip = streams.src_ip AND p.src_port = streams.src_port AND p.dst_ip = streams.dst_ip AND p.dst_port = streams.dst_port
                ORDER BY p.stream DESC LIMIT 1)
            WHERE capture_id = $c;
            """);

        // Messages without a direction of their own (Echo, counters) share the direction of their stream
        Run("""
            UPDATE messages SET dir = s.dir
            FROM streams s
            WHERE messages.capture_id = $c AND messages.dir IS NULL AND s.capture_id = $c AND s.stream = messages.stream AND s.dir IS NOT NULL;
            """);

        // A Return answers the latest preceding Call with the same return uid on the opposite direction of the same connection
        Run("""
            UPDATE messages SET reply_to = (
                SELECT c.id FROM messages c
                WHERE c.capture_id = messages.capture_id AND c.kind = 'Call' AND c.return_uid = messages.return_uid
                  AND c.src_ip = messages.dst_ip AND c.src_port = messages.dst_port AND c.dst_ip = messages.src_ip AND c.dst_port = messages.src_port
                  AND c.ts <= messages.ts
                ORDER BY c.ts DESC, c.id DESC LIMIT 1)
            WHERE capture_id = $c AND kind = 'Return' AND return_uid IS NOT NULL;
            """);

        // The Return itself does not say which method it belongs to, that is the Call's. ZDPSLib's own guess (the latest Call with that
        // return uid on any connection) is only kept when no Call was matched; a corrected Return is decoded again below.
        Run("""
            UPDATE messages SET service_id = c.service_id, service = c.service, method_id = c.method_id, method = c.method, decoded = NULL
            FROM messages c
            WHERE messages.capture_id = $c AND messages.kind = 'Return' AND c.id = messages.reply_to
              AND (messages.service_id IS NOT c.service_id OR messages.method_id IS NOT c.method_id);
            """);

        if (_storeDecoded)
            DecodeReturns(finish.Capture.Id, tx);

        long messageCount;
        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT COUNT(*) FROM messages WHERE capture_id = $c";
            cmd.Parameters.AddWithValue("$c", finish.Capture.Id);
            messageCount = (long)cmd.ExecuteScalar()!;
        }

        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                UPDATE captures SET started_at = $start, ended_at = $end, packet_count = $packets, message_count = $messages, pcap_bytes = $bytes, parsed_at = $now
                WHERE id = $c;
                """;
            cmd.Parameters.AddWithValue("$c", finish.Capture.Id);
            cmd.Parameters.AddWithValue("$start", (object?)finish.StartedAt ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$end", (object?)finish.EndedAt ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$packets", finish.PacketCount);
            cmd.Parameters.AddWithValue("$messages", messageCount);
            cmd.Parameters.AddWithValue("$bytes", finish.PcapBytes);
            cmd.Parameters.AddWithValue("$now", ToMicros(DateTime.UtcNow));
            cmd.ExecuteNonQuery();
        }
    }

    private void DecodeReturns(long captureId, SqliteTransaction tx)
    {
        var updates = new List<(long Id, string Json)>();
        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                SELECT id, service, method, payload FROM messages
                WHERE capture_id = $c AND kind = 'Return' AND decoded IS NULL AND method IS NOT NULL AND error IS NULL AND payload_len > 0;
                """;
            cmd.Parameters.AddWithValue("$c", captureId);
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
