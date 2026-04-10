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
    }

    public class ChatDiscordWebhookUrlConfig
    {
        public string[] ChannelNull { get; set; } = [];
        public string[] ChannelWorld { get; set; } = [];
        public string[] ChannelScene { get; set; } = [];
        public string[] ChannelTeam { get; set; } = [];
        public string[] ChannelUnion { get; set; } = [];
        public string[] ChannelPrivate { get; set; } = [];
        public string[] ChannelGroup { get; set; } = [];
        public string[] ChannelTopNotice { get; set; } = [];
        public string[] ChannelSystem { get; set; } = [];
    }
}
