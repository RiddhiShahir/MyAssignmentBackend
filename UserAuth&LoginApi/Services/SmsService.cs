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

// using Twilio;
// using Twilio.Rest.Api.V2010.Account;
// using Microsoft.Extensions.Configuration;
// using System.Threading.Tasks;

// namespace UserAuthLoginApi.Services
// {
//     public class SmsService : ISmsService
//     {
//         private readonly string _accountSid;
//         private readonly string _authToken;
//         private readonly string _fromNumber;

//         public SmsService(IConfiguration config)
//         {
//             _accountSid = config["Twilio:AccountSid"];
//             _authToken = config["Twilio:AuthToken"];
//             _fromNumber = config["Twilio:FromNumber"];
//         }

//         public async Task SendOtp(string mobile, string otp)
//         {
//             TwilioClient.Init(_accountSid, _authToken);
//             var message = await MessageResource.CreateAsync(
//                 body: $"Your verification OTP is: {otp}",
//                 from: new Twilio.Types.PhoneNumber(_fromNumber),
//                 to: new Twilio.Types.PhoneNumber(mobile)
//             );

//             if (message.Status == MessageResource.StatusEnum.Failed || message.Status == MessageResource.StatusEnum.Undelivered)
//             {
//                 throw new System.Exception($"Failed to send OTP to {mobile}: {message.ErrorMessage}");
//             }
//         }
//     }
// }