namespace UserAuthLoginApi.Services
{
    public class EmailService : IEmailService
    {
        public Task SendVerificationLink(string email, string link)
        {
            Console.WriteLine($"[EmailService] Sending email to {email}: {link}");
            return Task.CompletedTask;
        }
    }
}