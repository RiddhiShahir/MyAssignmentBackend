using System.ComponentModel.DataAnnotations.Schema;

namespace UserAuthLoginApi.Models
{
    public class LoginActivity
    {
        public int Id { get; set; }
        public string? Email { get; set; }
        public DateTime LoginTime { get; set; }
        public string? IpAddress { get; set; }
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User? User { get; set; }
    }
}
