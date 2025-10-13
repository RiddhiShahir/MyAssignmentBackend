using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using BCrypt.Net;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using UserAuthLoginApi.Data;
using UserAuthLoginApi.Models;
using UserAuthLoginApi.Models.DTOs;

namespace UserAuthLoginApi.Services
{
    public interface IAuthService
    {
        Task<string> Register(string name, string email, string mobile, string password);
        Task VerifyEmail(int userId, string token);
        Task RequestOtpAsync(string mobile);
        Task VerifyOtpAsync(string mobile, string otp);
        Task<object> LoginAsync(LoginDto dto, string ipAddress);
        Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken, string ipAddress);
        Task RequestTokenAsync(string identifier);
        Task SetPassword(int userId, string password);
    }

    public interface IEmailService
    {
        Task SendVerificationLink(string email, string link);
    }

    public interface ISmsService
    {
        Task SendOtp(string mobile, string otp);
    }

    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IEmailService _emailService;
        private readonly ISmsService _smsService;
        private readonly IConfiguration _config;

        public AuthService(AppDbContext context, IEmailService emailService, ISmsService smsService, IConfiguration config)
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
                //Password = password,
                CreatedDate = DateTime.UtcNow,
                IsEmailVerified = false,
                IsMobileVerified = false,
                IsVerified = false
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // ✅ Generate & store email verification token

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

            // ✅ Send email verification link with token

            var verificationLink = $"https://UserAuthLoginApi/verify/email?token={emailToken}&userId={user.UserId}";
            await _emailService.SendVerificationLink(email, verificationLink);

            // ✅ Generate & send OTP for mobile

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

        // ------------------ FORGOT PASSWORD ------------------

        public async Task<bool> ForgotPasswordAsync(ForgotPasswordDto dto)
        {
            if (string.IsNullOrEmpty(dto.email))
                throw new Exception("Email is required.");

            // ✅ Identify user
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == dto.email);

            if (user == null)
                throw new Exception("No account found with this email.");

            // ✅ Generate token
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));

            var resetRecord = new PasswordResetToken
            {
                UserId = user.UserId,
                Token = token,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            };

            _context.PasswordResetTokens.Add(resetRecord);
            await _context.SaveChangesAsync();

            // ✅ (Optional) Send token via email or SMS
            Console.WriteLine($"Password reset token for {user.Email}: {token}");

            return true;
        }

        // ------------------ RESET PASSWORD ------------------

        public async Task<bool> ResetPasswordAsync(ResetPasswordDto dto)
        {
            if (string.IsNullOrEmpty(dto.Token) || string.IsNullOrEmpty(dto.NewPassword))
                throw new Exception("Token and new password are required.");

            // ✅ Validate token
            var resetRecord = await _context.PasswordResetTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == dto.Token && !r.IsUsed && r.ExpiresAt > DateTime.UtcNow);

            if (resetRecord == null)
                throw new Exception("Invalid or expired reset token.");

            // ✅ Validate password strength
            if (!IsStrongPassword(dto.NewPassword))
                throw new Exception("Password must include upper, lower, number, and special character (min 8 chars).");

            // ✅ Update password
            if (resetRecord.User == null)
                throw new Exception("User not found for this reset token.");

            resetRecord.User.Password = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            resetRecord.User.LastUpdatedDate = DateTime.UtcNow;
            resetRecord.IsUsed = true;

            await _context.SaveChangesAsync();
            return true;
        }

        // ------------------ Password Handling ------------------

        public async Task SetPassword(int userId, string password)
        {
            if (!IsStrongPassword(password))
                throw new Exception("Weak password");

            var user = await _context.Users.FindAsync(userId);
            if (user == null) throw new Exception("User not found");

            user.Password = BCrypt.Net.BCrypt.HashPassword(password);
            user.LastUpdatedDate = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }

        private bool IsStrongPassword(string pw)
        {
            var regex = new System.Text.RegularExpressions.Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$");
            return regex.IsMatch(pw);
        }

        private string GenerateOtp() => new Random().Next(100000, 999999).ToString();

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

                // ✅ Verify OTP
                var otpEntry = await _context.Otp
                    .Where(o => o.Mobile == identifier && !o.IsUsed && o.ExpiryTime > DateTime.UtcNow)
                    .OrderByDescending(o => o.CreatedAt)
                    .FirstOrDefaultAsync();

                if (otpEntry == null || otpEntry.OtpCode != dto.Password)
                {
                    await LogLoginActivity(user.UserId, ipAddress, dto.LoginMethod, "Failed");
                    throw new UnauthorizedAccessException("Invalid or expired OTP.");
                }

                // ✅ Mark OTP as used
                otpEntry.IsUsed = true;
                await _context.SaveChangesAsync();

                // ✅ Mark mobile as verified if not already
                if (!user.IsMobileVerified)
                {
                    user.IsMobileVerified = true;
                    await _context.SaveChangesAsync();
                }

                // ✅ If email is not verified → stop login
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

            // ✅ Generate JWT, refresh token, etc. (same as before)
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


        // ✅ Helper method to log login activity
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


        // ------------------ REFRESH TOKEN ------------------

        public async Task<TokenResponseDto?> RefreshTokenAsync(string token, string ipAddress)
        {
            var rt = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token && !t.Revoked);
            if (rt == null || rt.ExpiresAt < DateTime.UtcNow)
                return null;

            var user = await _context.Users.FindAsync(rt.UserId);
            if (user == null)
                return null;

            rt.Revoked = true;

            var newRefresh = new RefreshToken
            {
                UserId = user.UserId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_config["JwtSettings:RefreshTokenDays"] ?? "30")),
                CreatedByIp = ipAddress
            };

            _context.RefreshTokens.Add(newRefresh);
            await _context.SaveChangesAsync();

            return new TokenResponseDto
            {
                AccessToken = CreateJwtToken(user),
                RefreshToken = newRefresh.Token,
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
            if (!user.IsMobileVerified)
                throw new Exception("Mobile not verified. Please verify before requesting OTP.");
            if (!user.IsEmailVerified)
                throw new Exception("Email not verified. Please verify before requesting OTP.");

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
                Mobile = mobile
            };

            _context.Otp.Add(otpEntry);
            await _context.SaveChangesAsync();

            Console.WriteLine($"OTP for {mobile}: {otp}");

            // return new
            // {
            //     message = "OTP sent successfully. Please verify within 5 minutes.",
            //     mobile = mobile
            // };
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
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.Email == email);

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
                var link = $"https://UserAuth&LoginApi/verify/token?token={token}&userId={user.UserId}";
                await _emailService.SendVerificationLink(user.Email, link);
            }
            else if (!string.IsNullOrEmpty(user.Mobile))
            {
                await _smsService.SendOtp(user.Mobile, token); // reuse SMS service
            }

        }

    }
}
