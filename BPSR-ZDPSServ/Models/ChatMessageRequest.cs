namespace BPSR_DeepsServ.Models
{
    public class ChatMessageRequest
    {
        public string Channel { get; set; } = string.Empty;
        public string SenderName { get; set; } = string.Empty;
        public long SenderId { get; set; }
        public DateTime Timestamp { get; set; }
        public string MessageType { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
    }
}
