namespace BPSR_DeepsServ.Models
{
    public class Settings
    {
        public bool EnableDiscordWebhookProxy { get; set; } = true;
        public bool EnableReportDeduplicationAPI { get; set; } = true;
        public TimeSpan DupeWindowDuration { get; set; } = TimeSpan.FromSeconds(10);
        public int DedupeListCleanUpAfterXEntries { get; set; } = 100;

        public bool EnableChatForwarding { get; set; } = false;
        public string ChatDiscordWebhookUrl { get; set; } = string.Empty;

        public ChatChannelFilter ChatAllowedChannels { get; set; } = new();
    }

    public class ChatChannelFilter
    {
        public bool ChannelNull { get; set; } = false;
        public bool ChannelWorld { get; set; } = false;
        public bool ChannelScene { get; set; } = false;
        public bool ChannelTeam { get; set; } = false;
        public bool ChannelUnion { get; set; } = false;
        public bool ChannelPrivate { get; set; } = false;
        public bool ChannelGroup { get; set; } = false;
        public bool ChannelTopNotice { get; set; } = false;
        public bool ChannelSystem { get; set; } = false;
    }
}
