using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using BCrypt.Net;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using UserAuthLoginApi.Data;
using UserAuthLoginApi.Models;
using UserAuthLoginApi.Models.DTOs;
using Twilio.Rest.Api.V2010.Account.AvailablePhoneNumberCountry;

namespace UserAuthLoginApi.Services
{
    public interface IAuthService // defines the contract for authentication-related operations.Declares a contract — any class that implements this must have these methods.
    {
        Task<string> Register(string name, string email, string mobile, string password);//Task<string> → async method, returns a message like "Verification sent".
        Task VerifyEmail(int userId, string token);// verifies email using userId and token.    
        Task RequestOtpAsync(string mobile);// sends OTP to the given mobile number.
        Task VerifyOtpAsync(string mobile, string otp);// verifies the OTP for the given mobile number.
        Task ForgotPasswordAsync(string? email);// initiates forgot password process for the given email.
        Task<object> LoginAsync(LoginDto dto, string ipAddress);// handles user login and returns tokens and user info.
        Task<bool> UpdateUserProfileAsync(string email, UpdateProfileDto dto);
        Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken, string ipAddress);
        Task<bool> ValidateTokenAsync(String token);// check if the given JWT token is valid.
        Task RequestTokenAsync(string identifier); // sends/resends a verification token to the user's email or mobile.
        Task VerifyOtp(int userId, string otp);
        Task ResetPasswordAsync(ResetPasswordDto dto); // resets password using the provided DTO.
        Task<UserProfileDto?> GetUserProfileAsync(string email); // retrieves user profile by email.
    }

    public interface IEmailService
    {
        Task SendVerificationLink(string email, string link);// sends a verification link to the specified email address.
    }

    public interface ISmsService
    {
        Task SendOtp(string mobile, string otp);// sends an OTP to the specified mobile number.
    }

    public class AuthService : IAuthService// implements the IAuthService interface, providing concrete logic for authentication operations.
    {
        private readonly AppDbContext _context;//private field to hold database context for data access
        private readonly IEmailService _emailService;//private field to hold email service for sending emails
        private readonly ISmsService _smsService;//private field to hold SMS service for sending OTPs
        private readonly IConfiguration _config;//private field to hold configuration settings(AppSettings.json/environment variables/jwtsecrets,etc..)
        public AuthService(AppDbContext context, IEmailService emailService, ISmsService smsService, IConfiguration config)// constructor to initialize the private fields with provided dependencies.
        {
            _context = context;
            _emailService = emailService;
            _smsService = smsService;
            _config = config;
        }

        // ------------------ Registration + Verification ------------------

        public async Task<string> Register(string name, string email, string mobile, string password)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(mobile))
                throw new ArgumentException("Name, email, and mobile cannot be empty.");

            if (_context.Users.Any(u => u.Email == email || u.Mobile == mobile))
                throw new Exception("Duplicate email or mobile");

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            var user = new User
            {
                Name = name,
                Email = email,
                Mobile = mobile,
                Password = hashedPassword,
                CreatedDate = DateTime.UtcNow,
                IsEmailVerified = false,
                IsMobileVerified = false,
                IsVerified = false
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            //  Generate & store email verification token

            var emailToken = Guid.NewGuid().ToString();

            var emailVerification = new EmailVerification
            {
                UserId = user.UserId,
                Email = user.Email!,
                Token = emailToken,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                IsUsed = false
            };

            await _context.EmailVerifications.AddAsync(emailVerification);
            await _context.SaveChangesAsync();

            //  Send email verification link with token

            var verificationLink = $"https://UserAuthLoginApi/verify/email?token={emailToken}&userId={user.UserId}";
            await _emailService.SendVerificationLink(email, verificationLink);

            //  Generate & send OTP for mobile

            var otp = GenerateOtp();
            await _smsService.SendOtp(mobile, otp);

            var otpEntry = new Otp
            {
                UserId = user.UserId,
                Mobile = user.Mobile,
                OtpCode = otp,
                ExpiryTime = DateTime.UtcNow.AddMinutes(5),
                CreatedAt = DateTime.UtcNow,
                IsUsed = false
            };
            await _context.Otp.AddAsync(otpEntry);
            await _context.SaveChangesAsync();

            return "Verification sent";
        }

        public async Task VerifyEmail(int userId, string token)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) throw new Exception("Invalid user ID");

            //validate token

            var verification = await _context.EmailVerifications
                .Where(e => e.UserId == userId && e.Token == token && !e.IsUsed)
                .OrderByDescending(e => e.CreatedAt)
                .FirstOrDefaultAsync();

            if (verification == null) throw new Exception("Invalid or expired token");
            if (DateTime.UtcNow > verification.ExpiresAt) throw new Exception("Verification link has expired");

            //mark email as verified(token used)

            verification.IsUsed = true;

            //update user status

            user.IsEmailVerified = true;

            // If both email and mobile verified, mark user as fully verified

            if (user.IsEmailVerified && user.IsMobileVerified)
                user.IsVerified = true;

            await _context.SaveChangesAsync();
        }

        public async Task VerifyOtp(int userId, string otp)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) throw new Exception("Invalid, user not found");

            var otpEntry = await _context.Otp
                .Where(o => o.UserId == userId && o.OtpCode == otp && !o.IsUsed)
                .OrderByDescending(o => o.CreatedAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null) throw new Exception("Invalid or expired OTP");

            // check expiration of OTP
            if (DateTime.UtcNow > otpEntry.ExpiryTime) throw new Exception("OTP has expired");

            //mark OTP as used
            otpEntry.IsUsed = true;
            otpEntry.UsedAt = DateTime.UtcNow;

            //update user mobile status verified 

            user.IsMobileVerified = true;
            if (user.IsEmailVerified && user.IsMobileVerified)
                user.IsVerified = true;

            await _context.SaveChangesAsync();
        }

        // ---------------- FORGOT PASSWORD ----------------
        public async Task ForgotPasswordAsync(string? email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                throw new Exception("User not found");

            if (!user.IsVerified)
                throw new Exception("Please verify your email before resetting password.");

            // Generate reset token
            string token = Guid.NewGuid().ToString();
            var expiry = DateTime.UtcNow.AddMinutes(5);

            var resetEntry = new PasswordResetToken
            {
                UserId = user.UserId,
                Token = token,
                ExpiresAt = expiry,
                IsUsed = false
            };

            _context.PasswordResetTokens.Add(resetEntry);
            await _context.SaveChangesAsync();

            // TODO: Send email with token (or reset link)
            //await _emailService.SendPasswordResetEmail(email, token);
            Console.WriteLine($"Password reset token for {email}: {token}");
        }

        // ---------------- RESET PASSWORD (via token)----------------
        public async Task ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                throw new Exception("User not found");

            var resetToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == user.UserId && t.Token == dto.Token && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow);

            if (resetToken == null)
                throw new Exception("Invalid or expired reset token.");

            if (resetToken.ExpiresAt < DateTime.UtcNow)
                throw new Exception("Reset token expired.");

            if (!IsStrongPassword(dto.NewPassword))
                throw new Exception("Weak password. Use uppercase, lowercase, number, and symbol.");

            user.Password = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            user.LastUpdatedDate = DateTime.UtcNow;

            resetToken.IsUsed = true;

            await _context.SaveChangesAsync();
        }

        // ---------------- CHANGE PASSWORD (Logged-in User) ----------------

        //     if (!IsStrongPassword(newPassword))
        //         throw new Exception("Weak password. Use uppercase, lowercase, number, and symbol.");

        //     user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
        //     user.LastUpdatedDate = DateTime.UtcNow;

        //     await _context.SaveChangesAsync();
        // }
        public async Task<(bool Success, string Message)> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return (false, "User not found");

            // Verify current password
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(currentPassword, user.Password);
            if (!isPasswordValid)
            return (false, "Current password is incorrect");

            //  Check strong password
             if (!IsStrongPassword(newPassword))
             return (false, "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.");
            

            // Prevent same password reuse
            bool isSamePassword = BCrypt.Net.BCrypt.Verify(newPassword, user.Password);
             if (isSamePassword)
             return (false, "New password cannot be the same as the current password.");

            // Update to new password 
            user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
            user.LastUpdatedDate = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return (true, "Password updated successfully");
        }

        // // Utility — Generate random reset token
        // private string GenerateResetToken()
        // {
        //     using (var rng = RandomNumberGenerator.Create())
        //     {
        //         byte[] bytes = new byte[32];
        //         rng.GetBytes(bytes);
        //         return Convert.ToBase64String(bytes);
        //     }
        // }


        // ------------------ LOGIN IMPLEMENTATION ------------------
        public async Task<object> LoginAsync(LoginDto dto, string ipAddress)
        {
            if (dto == null || string.IsNullOrEmpty(dto.Identifier))
                throw new Exception("Invalid login request");

            var identifier = dto.Identifier.Trim();
            User? user = null;

            if (dto.LoginMethod?.ToLower() == "email" || identifier.Contains("@"))
            {
                user = await _context.Users.FirstOrDefaultAsync(u => (u.Email ?? "").ToLower() == identifier.ToLower());
                if (user == null)
                    throw new UnauthorizedAccessException("No account found with this email.");

                if (!user.IsEmailVerified || !user.IsMobileVerified)
                    throw new UnauthorizedAccessException("Please verify both email and mobile before login.");

                if (string.IsNullOrEmpty(dto.Password))
                    throw new Exception("Password is required for email login.");

                bool isPasswordValid = BCrypt.Net.BCrypt.Verify(dto.Password, user.Password);
                if (!isPasswordValid)
                {
                    await LogLoginActivity(user.UserId, ipAddress, dto.LoginMethod, "Failed");
                    throw new UnauthorizedAccessException("Invalid password.");
                }
            }
            else if (dto.LoginMethod?.ToLower() == "mobile")
            {
                user = await _context.Users.FirstOrDefaultAsync(u => u.Mobile == identifier);
                if (user == null)
                    throw new UnauthorizedAccessException("No account found with this mobile number.");

                //  Verify OTP
                var otpEntry = await _context.Otp
                    .Where(o => o.Mobile == identifier && !o.IsUsed && o.ExpiryTime > DateTime.UtcNow)
                    .OrderByDescending(o => o.CreatedAt)
                    .FirstOrDefaultAsync();

                if (otpEntry == null || otpEntry.OtpCode != dto.Password)
                {
                    await LogLoginActivity(user.UserId, ipAddress, dto.LoginMethod, "Failed");
                    throw new UnauthorizedAccessException("Invalid or expired OTP.");
                }

                //  Mark OTP as used
                otpEntry.IsUsed = true;
                await _context.SaveChangesAsync();

                //  Mark mobile as verified if not already
                if (!user.IsMobileVerified)
                {
                    user.IsMobileVerified = true;
                    await _context.SaveChangesAsync();
                }

                //  If email is not verified → stop login
                if (!user.IsEmailVerified)
                {
                    await LogLoginActivity(user.UserId, ipAddress, dto.LoginMethod, "Failed");
                    throw new UnauthorizedAccessException("Email not verified. Please verify before login.");
                }
            }
            else
            {
                throw new Exception("Invalid login method. Use 'email' or 'mobile'.");
            }

            //  Generate JWT, refresh token, etc.
            var jwt = CreateJwtToken(user);
            var refresh = new RefreshToken
            {
                UserId = user.UserId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_config["JwtSettings:RefreshTokenMinutes"] ?? "30")),
                CreatedByIp = ipAddress
            };
            _context.RefreshTokens.Add(refresh);
            await _context.SaveChangesAsync();

            await LogLoginActivity(user.UserId, ipAddress, dto.LoginMethod, "Success");

            return new
            {
                message = "Login successful",
                accessToken = jwt,
                refreshToken = refresh.Token,
                expiresInSeconds = int.Parse(_config["JwtSettings:AccessTokenMinutes"] ?? "30") * 60,
                userId = user.UserId,
                name = user.Name,
                email = user.Email
            };
        }

        // Helper method to log login activity
        private async Task LogLoginActivity(int userId, string ipAddress, string? loginMethod, string status)
        {
            if (userId <= 0) return; // prevent FK errors

            var loginActivity = new LoginActivity
            {
                UserId = userId,
                IpAddress = ipAddress,
                LoginMethod = loginMethod,
                Status = status,
                LoginTime = DateTime.UtcNow
            };

            _context.LoginActivity.Add(loginActivity);
            await _context.SaveChangesAsync();
        }

        // ------VALIDATE TOKEN------------------

        public async Task<bool> ValidateTokenAsync(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_config["JwtSettings:Key"] ?? throw new InvalidOperationException("JWT Key is missing"));

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _config["JwtSettings:Issuer"],
                    ValidAudience = _config["JwtSettings:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "sub").Value);

                var user = await _context.Users.FindAsync(userId);
                return user != null;
            }
            catch
            {
                return false;
            }
        }

        // ------------------ REFRESH TOKEN ------------------
        public async Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken, string ipAddress)
        {
            if (string.IsNullOrEmpty(refreshToken))
                throw new ArgumentException("Refresh token is required");

            var existingToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == refreshToken); // && rt.ExpiresAt > DateTime.UtcNow);

            if (existingToken == null)
                throw new UnauthorizedAccessException("Invalid or expired refresh token");

            // Check if refresh token expired
            if (existingToken.ExpiresAt <= DateTime.UtcNow)
            {
                existingToken.Revoked = true;
                await _context.SaveChangesAsync();
                throw new UnauthorizedAccessException("Refresh token expired, please login again");
            }

            var user = await _context.Users.FindAsync(existingToken.UserId);
            if (user == null)
            {
                existingToken.Revoked = true;
                await _context.SaveChangesAsync();
                throw new UnauthorizedAccessException("User not found");
            }

            // Generate new token

            var newAccessToken = CreateJwtToken(user);
            var newRefreshToken = new RefreshToken
            {
                UserId = user.UserId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_config["JwtSettings:RefreshTokenMinutes"] ?? "30")),
                CreatedByIp = ipAddress
            };

            //store and remove old one
            _context.RefreshTokens.Add(newRefreshToken);
            _context.RefreshTokens.Remove(existingToken);
            await _context.SaveChangesAsync();

            return new TokenResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token,
                ExpiresInSeconds = int.Parse(_config["JwtSettings:AccessTokenMinutes"] ?? "30") * 60
            };
        }

        // ------------------ JWT CREATION ------------------
        private string CreateJwtToken(User user)
        {
            var jwtSettings = _config.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["AccessTokenMinutes"] ?? "30"));

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),

                // This is critical: it allows [Authorize] and User.Identity.Name to work
                new Claim(ClaimTypes.Name, user.Email ?? string.Empty),

                new Claim(ClaimTypes.Role, user.Role ?? "User"),
                new Claim("name", user.Name ?? string.Empty)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task RequestOtpAsync(string mobile)
        {
            // find user by  mobile
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                 u.Mobile == mobile);

            if (user == null)
                throw new Exception("User with this mobile number not found.");

            // verify if email and mobile verified as per your flow
            // if (!user.IsMobileVerified)
            //     throw new Exception("Mobile not verified. Please verify before requesting OTP.");
            // if (!user.IsEmailVerified)
            //     throw new Exception("Email not verified. Please verify before requesting OTP.");

            // Generate random OTP
            var otp = new Random().Next(100000, 999999).ToString();

            // Save to DB
            var otpEntry = new Otp
            {
                UserId = user.UserId,
                OtpCode = otp,
                CreatedAt = DateTime.UtcNow,
                ExpiryTime = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false,
                Mobile = mobile,
                UsedAt = DateTime.UtcNow
            };

            _context.Otp.Add(otpEntry);
            await _context.SaveChangesAsync();
            //     await _smsService.SendOtp(mobile, otp);

            Console.WriteLine($"OTP for {mobile}: {otp}");
        }


        public async Task VerifyOtpAsync(string mobile, string otp)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u =>
            u.Mobile == mobile);

            if (user == null)
                throw new Exception("User not found.");

            var otpEntry = await _context.Otp
                .Where(o => o.UserId == user.UserId && o.OtpCode == otp && !o.IsUsed)
                .OrderByDescending(o => o.CreatedAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null) throw new Exception("Invalid or expired OTP");
            if (DateTime.UtcNow > otpEntry.ExpiryTime) throw new Exception("OTP has expired");

            otpEntry.IsUsed = true;
            user.IsVerified = true;
            otpEntry.UsedAt = DateTime.UtcNow;

            user.IsMobileVerified = true;
            if (user.IsEmailVerified && user.IsMobileVerified)
                user.IsVerified = true;

            await _context.SaveChangesAsync();
        }

        public async Task RequestTokenAsync(string email)
        {
            // Find user by email 
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
                throw new Exception("User not found.");

            // Generate secure token
            var token = Guid.NewGuid().ToString();

            // Save token in DB
            var emailVerification = new EmailVerification
            {
                UserId = user.UserId,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10), // token valid for 10 minutes
                IsUsed = false,
                Email = user.Email!,
            };
            await _context.EmailVerifications.AddAsync(emailVerification);
            await _context.SaveChangesAsync();
            Console.WriteLine($"[RequestToken] Token for {email}: {token}");


            // Example: send token via email (or SMS)
            if (!string.IsNullOrEmpty(user.Email))
            {
                var link = $"https://UserAuthLoginApi/verify/email?token={token}&userId={user.UserId}";
                await _emailService.SendVerificationLink(user.Email, link);
            }
            else if (!string.IsNullOrEmpty(user.Mobile))
            {
                await _smsService.SendOtp(user.Mobile, token); // reuse SMS service
            }

        }
        // ------------------- Helper: Generate OTP -------------------
        private string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
            // OR by using
            // private string GenerateOtp() => new Random().Next(100000, 999999).ToString();
        }

        // ------------------- Helper: Check Password Strength -------------------
        private bool IsStrongPassword(string password)
        {
            // Minimum 8 characters, at least one uppercase, one lowercase, one digit, and one special character
            if (string.IsNullOrWhiteSpace(password)) return false;
            if (password.Length < 8) return false;
            if (!password.Any(char.IsUpper)) return false;
            if (!password.Any(char.IsLower)) return false;
            if (!password.Any(char.IsDigit)) return false;
            if (!password.Any(ch => "!@#$%^&*()_+-=[]{}|;':\",.<>?".Contains(ch))) return false;

            return true;
            // OR using
            //     var regex = new System.Text.RegularExpressions.Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$");
            //     return regex.IsMatch(password);
        }

        public async Task<UserProfileDto?> GetUserProfileAsync(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return null;

            return new UserProfileDto
            {
                Id = user.UserId,
                Name = user.Name,
                Email = user.Email,
                Mobile = user.Mobile,
                CreatedAt = user.CreatedDate,
                LastUpdatedDate = user.LastUpdatedDate
            };
        }

        public async Task<bool> UpdateUserProfileAsync(string email, UpdateProfileDto dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return false;

            if (!string.IsNullOrEmpty(dto.Name))
                user.Name = dto.Name;

            if (!string.IsNullOrEmpty(dto.Mobile))
                user.Mobile = dto.Mobile;

            if (!string.IsNullOrEmpty(dto.Email))
                user.Email = dto.Email;

            user.LastUpdatedDate = DateTime.UtcNow;

            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            return true;
        }


    }
}
