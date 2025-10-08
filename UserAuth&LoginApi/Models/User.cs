using System.ComponentModel.DataAnnotations;

namespace UserAuthLoginApi.Models
{
    public class User
    {
        public int UserId { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Mobile { get; set; }
        public string? Password { get; set; }
        public string Role { get; set; } = "User";
        public bool IsVerified { get; set; } = false;
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdatedDate { get; set; } = DateTime.UtcNow;
        public bool IsEmailVerified { get; set; } = false;
        public bool IsMobileVerified { get; set; } = false;

         // Navigation properties
        public ICollection<Otp>? Otps { get; set; }
        public ICollection<LoginActivity>? LoginActivities { get; set; }
    }

    public class EmailVerificationToken
    {
        [Key]
        public int Id { get; set; } 
        [Required]
        public int UserId { get; set; }
        [Required]
        public string Token { get; set; } = null!;
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; } = false;
    }
    
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; } 
        [Required]
        public int UserId { get; set; }
        [Required]
        public string Token { get; set; } = null!;
        public DateTime ExpiresAt { get; set; }
        public bool Revoked { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string CreatedByIp { get; set; } = null!;
    }

}