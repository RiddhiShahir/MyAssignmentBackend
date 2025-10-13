namespace UserAuthLoginApi.Models.DTOs
{
    public class ForgotPasswordDto
    {
        public string? email { get; set; } 
    }

    public class ResetPasswordDto
    {
        public string? Token { get; set; }
        public string? NewPassword { get; set; }
    }

    public class SetPasswordRequest
    {
        public int UserId { get; set; }
        public string? Password { get; set; }
    }
}
