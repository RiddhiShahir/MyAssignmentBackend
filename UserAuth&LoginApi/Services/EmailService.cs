namespace UserAuthLoginApi.Services
{
    public class EmailService : IEmailService
    {
        public Task SendVerificationLink(string email, string link)
        {
            Console.WriteLine($"[EmailService] Sending email to {email}: {link}");
            return Task.CompletedTask;
        }

        public Task SendPasswordResetEmail(string email, string token)
        {
            var resetLink = $"https://yourapp.com/reset-password?token={token}";
            Console.WriteLine($"[EmailService] Sending email to {email}: {resetLink}");
            return Task.CompletedTask;
        }
    }
}

// using SendGrid;
// using SendGrid.Helpers.Mail;
// using System.Threading.Tasks;
// using Microsoft.Extensions.Configuration;

// namespace UserAuthLoginApi.Services
// {
//     public class EmailService : IEmailService
//     {
//         private readonly string _apiKey;
//         private readonly string _fromEmail;
//         private readonly string _fromName;

//         public EmailService(IConfiguration config)
//         {
//             _apiKey = config["SendGrid:ApiKey"];
//             _fromEmail = config["SendGrid:FromEmail"];
//             _fromName = config["SendGrid:FromName"];
//         }

//         public async Task SendVerificationLink(string email, string link)
//         {
//             var client = new SendGridClient(_apiKey);
//             var from = new EmailAddress(_fromEmail, _fromName);
//             var to = new EmailAddress(email);
//             var subject = "Verify Your Email";
//             var plainTextContent = $"Please verify your email by clicking this link: {link}";
//             var htmlContent = $"<p>Please verify your email by clicking <a href='{link}'>here</a>.</p>";
//             var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
//             var response = await client.SendEmailAsync(msg);

//             if (response.StatusCode != System.Net.HttpStatusCode.OK && response.StatusCode != System.Net.HttpStatusCode.Accepted)
//             {
//                 throw new System.Exception("Failed to send verification email.");
//             }
//         }

//         public async Task SendPasswordResetEmail(string email, string token)
//         {
//             var resetLink = $"https://yourapp.com/reset-password?token={token}";
//             var client = new SendGridClient(_apiKey);
//             var from = new EmailAddress(_fromEmail, _fromName);
//             var to = new EmailAddress(email);
//             var subject = "Reset Your Password";
//             var plainTextContent = $"Click this link to reset your password: {resetLink}";
//             var htmlContent = $"<p>Click <a href='{resetLink}'>here</a> to reset your password.</p>";
//             var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
//             var response = await client.SendEmailAsync(msg);

//             if (response.StatusCode != System.Net.HttpStatusCode.OK && response.StatusCode != System.Net.HttpStatusCode.Accepted)
//             {
//                 throw new System.Exception("Failed to send password reset email.");
//             }
//         }
//     }
// }