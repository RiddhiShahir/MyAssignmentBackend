namespace UserAuthLoginApi.Services
{
    public class SmsService : ISmsService
    {
        public Task SendOtp(string mobile, string otp)
        {
            Console.WriteLine($"[SmsService] Sending OTP to {mobile}: {otp}");
            return Task.CompletedTask;
        }
    }
}