using System.Text;
using System.Text.RegularExpressions;

namespace BPSR_DeepsServ.Models
{
    public class Settings
    {
        public bool EnableDiscordWebhookProxy { get; set; } = true;
        public bool EnableReportDeduplicationAPI { get; set; } = true;
        public TimeSpan DupeWindowDuration { get; set; } = TimeSpan.FromSeconds(10);
        public int DedupeListCleanUpAfterXEntries { get; set; } = 100;

        public bool EnableChatForwarding { get; set; } = false;
        public ChatDiscordWebhookUrlConfig ChatDiscordWebhookUrls { get; set; } = new();

        public bool EnableNotificationForwarding { get; set; } = false;
        public string[] NotificationDiscordWebhookUrls { get; set; } = [];
    }

    public class ChatDiscordWebhookUrlConfig
    {
        public ChatDiscordWebhookConfig[] ChannelNull { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelWorld { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelScene { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelTeam { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelUnion { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelPrivate { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelGroup { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelTopNotice { get; set; } = [];
        public ChatDiscordWebhookConfig[] ChannelSystem { get; set; } = [];
    }

    public class ChatDiscordWebhookConfig
    {
        private Regex? _regex;
        private string? _filter;

        public string Url { get; set; } = string.Empty;

        /// <summary>Optional regex; only messages whose text matches (after NFKC normalization of both pattern and text, so full/half-width forms are equivalent) are forwarded. Empty = forward all.</summary>
        public string? Filter
        {
            get => _filter;
            set
            {
                _filter = value;
                _regex = string.IsNullOrEmpty(value) ? null : new Regex(value.Normalize(NormalizationForm.FormKC), RegexOptions.Compiled);
            }
        }

        public bool Matches(string text) => _regex == null || _regex.IsMatch(text.Normalize(NormalizationForm.FormKC));
    }
}
