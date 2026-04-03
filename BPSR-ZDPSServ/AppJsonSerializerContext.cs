using BPSR_DeepsServ.Models;
using System.Text.Json.Serialization;

namespace BPSR_DeepsServ
{
    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(HttpResponseMessage))]
    [JsonSerializable(typeof(Settings))]
    [JsonSerializable(typeof(DedupeResp))]
    [JsonSerializable(typeof(ChatMessageRequest))]
    [JsonSerializable(typeof(DiscordChatPayload))]
    internal partial class AppJsonSerializerContext : JsonSerializerContext
    {

    }
}
