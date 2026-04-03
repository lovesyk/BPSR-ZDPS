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
            var webhookUrl = settings.Value.ChatDiscordWebhookUrl;
            if (string.IsNullOrEmpty(webhookUrl))
                return;

            var filter = settings.Value.ChatAllowedChannels;
            var allowed = chatMessage.Channel switch
            {
                "ChannelNull"       => filter.ChannelNull,
                "ChannelWorld"      => filter.ChannelWorld,
                "ChannelScene"      => filter.ChannelScene,
                "ChannelTeam"       => filter.ChannelTeam,
                "ChannelUnion"      => filter.ChannelUnion,
                "ChannelPrivate"    => filter.ChannelPrivate,
                "ChannelGroup"      => filter.ChannelGroup,
                "ChannelTopNotice"  => filter.ChannelTopNotice,
                "ChannelSystem"     => filter.ChannelSystem,
                _                   => false
            };
            if (!allowed)
                return;

            var (label, emoji) = chatMessage.Channel switch
            {
                "ChannelWorld" => ("ワールド", "🟣"),
                "ChannelUnion" => ("ギルド",   "🟢"),
                "ChannelTeam"  => ("パーティ", "🔵"),
                _              => ("その他",   "🟡")
            };
            var discordPayload = new DiscordChatPayload
            {
                Content = $"{(string.IsNullOrEmpty(chatMessage.SenderName) ? "" : $"**{chatMessage.SenderName}** ")}{chatMessage.Timestamp:HH:mm}\n[{emoji}{label}]{chatMessage.Text}"
            };
            var discordJson = System.Text.Json.JsonSerializer.Serialize(discordPayload, AppJsonSerializerContext.Default.DiscordChatPayload);

                using var content = new StringContent(discordJson, Encoding.UTF8, "application/json");
                await HttpClient.PostAsync(webhookUrl, content);
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
