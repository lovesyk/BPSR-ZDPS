using BPSR_ZDPSLib;
using Serilog;
using static Zproto.GrpcTeamNtf.Types;

namespace BPSR_ZDPSMessenger;

public class NotificationHandler(MessengerConfig config)
{
    private readonly HttpClient _httpClient = new();

    public void OnNotifyInvitation(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyInvitation.Parser.ParseFrom(span);
        if (msg == null) return;

        var charId = msg.VRequest.InviteMemData?.BasicData?.CharId;
        var name = msg.VRequest.InviteMemData?.BasicData?.Name;

        Log.Information("[NotifyInvitation] {Name} ({CharId})", name, charId);
        _ = SendToApiAsync("NotifyInvitation", charId, name);
    }

    public void OnNotifyApplyJoin(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyApplyJoin.Parser.ParseFrom(span);
        if (msg == null) return;

        var charId = msg.VRequest.Apply?.CharId;
        var name = msg.VRequest.Apply?.UserSummaryData?.BasicData?.Name;

        Log.Information("[NotifyApplyJoin] {Name} ({CharId})", name, charId);
        _ = SendToApiAsync("NotifyApplyJoin", charId, name);
    }

    public void OnNotifyRefuseInvite(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyRefuseInvite.Parser.ParseFrom(span);
        if (msg == null) return;

        var charId = msg.VRequest.InviteesId == 0 ? (long?)null : (long)msg.VRequest.InviteesId;
        var name = string.IsNullOrEmpty(msg.VRequest.InviteesName) ? null : msg.VRequest.InviteesName;

        Log.Information("[NotifyRefuseInvite] {Name} ({CharId})", name, charId);
        _ = SendToApiAsync("NotifyRefuseInvite", charId, name);
    }

    public void OnNotifyLeaderApplyListSize(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyLeaderApplyListSize.Parser.ParseFrom(span);
        if (msg == null) return;

        Log.Information("[NotifyLeaderApplyListSize] Size={Size}", msg.VRequest.VSize);
        _ = SendToApiAsync("NotifyLeaderApplyListSize", null, null);
    }

    public void OnNotifyApplyBeLeader(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyApplyBeLeader.Parser.ParseFrom(span);
        if (msg == null) return;

        var charId = msg.VRequest.MemData?.BasicData?.CharId;
        var name = msg.VRequest.MemData?.BasicData?.Name;

        Log.Information("[NotifyApplyBeLeader] {Name} ({CharId})", name, charId);
        _ = SendToApiAsync("NotifyApplyBeLeader", charId, name);
    }

    private async Task SendToApiAsync(string notificationType, long? charId, string? name)
    {
        var urls = config.NotificationEndpoints;
        if (urls.Length == 0)
            return;

        var payload = new
        {
            NotificationType = notificationType,
            CharId = charId,
            Name = name
        };

        var json = System.Text.Json.JsonSerializer.Serialize(payload);
        foreach (var url in urls)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            try
            {
                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    Log.Warning("Failed to send notification to API: {StatusCode}", response.StatusCode);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error sending notification to API");
            }
        }
    }
}
