using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserAuthLoginApi.Models
{
    public class LoginActivity
    {
         [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ActivityId { get; set; }
        public DateTime LoginTime { get; set; } = DateTime.UtcNow;
        public string? IpAddress { get; set; }
        public int UserId { get; set; }

        public string? DeviceId { get; set; } 
        public string? LoginMethod { get; set; } 
        public string? Status { get; set; } 

        [ForeignKey("UserId")]
        public User? User { get; set; }
    }
}
