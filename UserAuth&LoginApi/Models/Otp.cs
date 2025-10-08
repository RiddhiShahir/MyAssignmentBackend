using System.ComponentModel.DataAnnotations.Schema;

namespace UserAuthLoginApi.Models
{
    public class Otp
    {
        public int OtpId { get; set; }
        public int UserId { get; set; }
        public string? OtpCode { get; set; }
        public string? Mobile { get; set; }
        public DateTime ExpiryTime { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public bool IsUsed { get; set; } = false;
        public DateTime? UsedAt { get; set; }


        [ForeignKey("UserId")]
        public User? User { get; set; }
    }
}