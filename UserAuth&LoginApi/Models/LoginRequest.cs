namespace UserAuthLoginApi.Models
{
    public class LoginRequest
    {
        public string? LoginMethod { get; set; }  // "email" or "mobile"
        public string? Identifier { get; set; }   // email or mobile number
        public string? Password { get; set; }
    }
}
