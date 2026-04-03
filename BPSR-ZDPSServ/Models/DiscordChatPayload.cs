using System.Text.Json.Serialization;

namespace BPSR_DeepsServ.Models
{
    public class DiscordChatPayload
    {
        [JsonPropertyName("content")]
        public string Content { get; set; } = string.Empty;
    }
}
