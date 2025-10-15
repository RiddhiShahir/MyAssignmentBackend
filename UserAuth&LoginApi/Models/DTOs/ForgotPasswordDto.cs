namespace UserAuthLoginApi.Models.DTOs
{
    public class ForgotPasswordDto
    {
        public string? email { get; set; } 
    }

    public class ResetPasswordDto
    {
        public string Email { get; set; } = string.Empty;
        public string? Token { get; set; }
       public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class SetPasswordRequest
    {
        public int UserId { get; set; }
        public string? Password { get; set; }
    }
}
