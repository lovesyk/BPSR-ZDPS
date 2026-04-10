using BPSR_ZDPSLib;
using Serilog;
using Zproto;
using static Zproto.ChitChatNtf.Types;

namespace BPSR_ZDPSMessenger;

public class ChatHandler(MessengerConfig config)
{
    private readonly HttpClient _httpClient = new();

    public void OnChatMessage(ReadOnlySpan<byte> span, ExtraPacketData extraData)
    {
        var msg = NotifyNewestChitChatMsgs.Parser.ParseFrom(span);
        if (msg == null)
            return;

        var channel = msg.VRequest.ChannelType;
        var senderId = msg.VRequest.ChatMsg.SendCharInfo.CharId;
        var senderName = msg.VRequest.ChatMsg.SendCharInfo.Name;
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(msg.VRequest.ChatMsg.Timestamp).LocalDateTime;
        var msgInfo = msg.VRequest.ChatMsg.MsgInfo;

        Print(channel, senderName, senderId, timestamp, msgInfo);

        _ = SendToApiAsync(channel, senderName, senderId, timestamp, msgInfo);
    }

    private void Print(ChitChatChannelType channel, string senderName, long senderId, DateTime timestamp, ChatMsgInfo msgInfo)
    {
        var text = msgInfo.MsgType switch
        {
            ChitChatMsgType.ChatMsgTextMessage or ChitChatMsgType.ChatMsgTextNotice => msgInfo.MsgText,
            ChitChatMsgType.ChatMsgPictureEmoji => $"[Emoji:{msgInfo.PictureEmoji?.ConfigId}]",
            ChitChatMsgType.ChatMsgVoice => $"[Voice:{msgInfo.Voice?.Seconds}s]",
            ChitChatMsgType.ChatMsgHypertext => $"[Hypertext:{msgInfo.ChatHypertext?.ConfigId}]",
            ChitChatMsgType.ChatMsgMultiLangNotice => $"[Notice:{msgInfo.MultiLangNotice?.ConfigId}]",
            _ => $"[{msgInfo.MsgType}]"
        };

        Log.Information("[{Timestamp:HH:mm:ss}] [{Channel}] {SenderName} ({SenderId}): {Text}",
            timestamp, channel, senderName, senderId, text);
    }

    private async Task SendToApiAsync(ChitChatChannelType channel, string senderName, long senderId, DateTime timestamp, ChatMsgInfo msgInfo)
    {
        var endpoints = config.ChatEndpoints;
        var urls = channel switch
        {
            ChitChatChannelType.ChannelNull      => endpoints.ChannelNull,
            ChitChatChannelType.ChannelWorld     => endpoints.ChannelWorld,
            ChitChatChannelType.ChannelScene     => endpoints.ChannelScene,
            ChitChatChannelType.ChannelTeam      => endpoints.ChannelTeam,
            ChitChatChannelType.ChannelUnion     => endpoints.ChannelUnion,
            ChitChatChannelType.ChannelPrivate   => endpoints.ChannelPrivate,
            ChitChatChannelType.ChannelGroup     => endpoints.ChannelGroup,
            ChitChatChannelType.ChannelTopNotice => endpoints.ChannelTopNotice,
            ChitChatChannelType.ChannelSystem    => endpoints.ChannelSystem,
            _                                    => []
        };
        if (urls.Length == 0)
            return;

        var text = msgInfo.MsgType switch
        {
            ChitChatMsgType.ChatMsgTextMessage or ChitChatMsgType.ChatMsgTextNotice => msgInfo.MsgText,
            ChitChatMsgType.ChatMsgPictureEmoji => $"[Emoji:{msgInfo.PictureEmoji?.ConfigId}]",
            ChitChatMsgType.ChatMsgVoice => $"[Voice:{msgInfo.Voice?.Seconds}s]",
            ChitChatMsgType.ChatMsgHypertext => $"[Hypertext:{msgInfo.ChatHypertext?.ConfigId}]",
            ChitChatMsgType.ChatMsgMultiLangNotice => $"[Notice:{msgInfo.MultiLangNotice?.ConfigId}]",
            _ => $"[{msgInfo.MsgType}]"
        };

        var payload = new
        {
            Channel = channel.ToString(),
            SenderName = senderName,
            SenderId = senderId,
            Timestamp = timestamp,
            MessageType = msgInfo.MsgType.ToString(),
            Text = text
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
                    Log.Warning("Failed to send chat message to API: {StatusCode}", response.StatusCode);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error sending chat message to API");
            }
        }
    }
}
