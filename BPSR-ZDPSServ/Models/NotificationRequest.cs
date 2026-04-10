namespace BPSR_DeepsServ.Models
{
    public class NotificationRequest
    {
        public string NotificationType { get; set; } = string.Empty;
        public long? CharId { get; set; }
        public string? Name { get; set; }
    }
}
