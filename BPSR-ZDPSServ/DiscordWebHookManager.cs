using BPSR_DeepsServ.Models;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.IO.Hashing;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;

namespace BPSR_DeepsServ
{
    public class DiscordWebHookManager(IOptions<Settings> settings, ILogger<DiscordWebHookManager> logger) : DedupeManager(settings)
    {
        private readonly HttpClient HttpClient = new ();

        public async Task<HttpResponseMessage> ProcessEncounterReport(string id, string token, ulong teamId, string payload, IFormFileCollection files)
        {
            if (IsDupe(id, token, teamId))
            {
                return new HttpResponseMessage(HttpStatusCode.AlreadyReported);
            }

            var sendUrl = $"https://discord.com/api/webhooks/{id}/{token}";
            var result = await SendWebhook(sendUrl, payload, files);

            return result;
        }

        private bool IsDupe(string discordId, string discordToken, ulong teamId)
        {
            var id = CreateTeamHookReportId(discordId, discordToken, teamId);
            var isDupe = IsDupe(id);

            return isDupe;
        }

        private ulong CreateTeamHookReportId(string id, string token, ulong teamId)
        {
            var hash = new XxHash64();
            hash.Append(MemoryMarshal.Cast<ulong, byte>([teamId]));
            hash.Append(Encoding.UTF8.GetBytes(id));
            hash.Append(Encoding.UTF8.GetBytes(token));
            var hashUlong = hash.GetCurrentHashAsUInt64();

            return hashUlong;
        }

        public async Task ForwardChatMessage(ChatMessageRequest chatMessage)
        {
            try
            {
                var webhookUrls = settings.Value.ChatDiscordWebhookUrls;
                var urls = chatMessage.Channel switch
                {
                    "ChannelNull"       => webhookUrls.ChannelNull,
                    "ChannelWorld"      => webhookUrls.ChannelWorld,
                    "ChannelScene"      => webhookUrls.ChannelScene,
                    "ChannelTeam"       => webhookUrls.ChannelTeam,
                    "ChannelUnion"      => webhookUrls.ChannelUnion,
                    "ChannelPrivate"    => webhookUrls.ChannelPrivate,
                    "ChannelGroup"      => webhookUrls.ChannelGroup,
                    "ChannelTopNotice"  => webhookUrls.ChannelTopNotice,
                    "ChannelSystem"     => webhookUrls.ChannelSystem,
                    _                   => []
                };
                if (urls.Length == 0)
                    return;

                var (label, emoji) = chatMessage.Channel switch
                {
                    "ChannelWorld"   => ("ワールド",     "🟣"),
                    "ChannelUnion"   => ("ギルド",       "🟢"),
                    "ChannelTeam"    => ("パーティ",     "🔵"),
                    "ChannelScene"   => ("チャンネル",   "⚫"),
                    "ChannelPrivate" => ("プライベート", "🟡"),
                    _                => ("その他",       "⚫")
                };
                var discordPayload = new DiscordChatPayload
                {
                    Content = $"{(string.IsNullOrEmpty(chatMessage.SenderName) ? "" : $"**{chatMessage.SenderName}** ")}{chatMessage.Timestamp:HH:mm}\n[{emoji}{label}]{chatMessage.Text}"
                };
                var discordJson = System.Text.Json.JsonSerializer.Serialize(discordPayload, AppJsonSerializerContext.Default.DiscordChatPayload);

                foreach (var url in urls)
                {
                    using var content = new StringContent(discordJson, Encoding.UTF8, "application/json");
                    await HttpClient.PostAsync(url, content);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to forward chat message to Discord webhook");
            }
        }

        private async Task<HttpResponseMessage> SendWebhook(string url, string payload, IFormFileCollection files)
        {
            try
            {
                using var form = new MultipartFormDataContent();
                form.Add(new StringContent(payload, Encoding.UTF8, "application/json"), "payload_json");

                foreach (var file in files)
                {
                    var fileStream = file.OpenReadStream();
                    var fileContent = new StreamContent(fileStream);
                    fileContent.Headers.ContentType = new MediaTypeHeaderValue(file.ContentType);
                    form.Add(fileContent, file.Name, file.FileName);
                }

                var response = await HttpClient.PostAsync(url, form);

                return response;
            }
            catch (Exception ex)
            {

            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }
    }
}
