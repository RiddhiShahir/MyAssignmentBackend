using System.ComponentModel.DataAnnotations;

namespace UserAuthLoginApi.Models.DTOs
{
    public class RegisterRequest
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Mobile { get; set; }
        public string? Password { get; set; }
        public string Role { get; set; } = "User";
    }
    
    public class LoginDto
    {
         public string? LoginMethod { get; set; }  // "email" or "mobile"
        [Required] public string Identifier { get; set; } = null!; // email or mobile
        [Required] public string Password { get; set; } = null!;
    }

    public class VerifyEmailDto
    {
        [Required] public string Token { get; set; } = null!;
    }

    public class RequestOtpDto
    {
        [Required] public string Mobile { get; set; } = null!;
    }

    public class VerifyOtpDto
    {
        // [Required] public string Mobile { get; set; } = null!;
        [Required] public string Otp { get; set; } = null!;
    }

    public class TokenResponseDto
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresInSeconds { get; set; }
    }

}