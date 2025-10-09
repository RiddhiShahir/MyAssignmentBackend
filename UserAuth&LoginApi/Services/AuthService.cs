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
        //private readonly PasswordHasher<User> _passwordHasher;

        public AuthService(AppDbContext context, IEmailService emailService, ISmsService smsService, IConfiguration config)
        {
            _context = context;
            _emailService = emailService;
            _smsService = smsService;
            _config = config;
            //_passwordHasher = new PasswordHasher<User>();
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

        public async Task<Object> LoginAsync(LoginDto dto, string ipAddress)
        {
            if (dto == null || string.IsNullOrEmpty(dto.Identifier) || string.IsNullOrEmpty(dto.Password))
                throw new Exception("Invalid login request");

            var identifier = dto.Identifier.Trim();
            User? user = null;

            // ✅ Determine login method

            if (string.IsNullOrEmpty(identifier))
                throw new ArgumentException("Identifier cannot be null or empty.");

            if (dto.LoginMethod?.ToLower() == "email" || identifier.Contains("@"))
                user = await _context.Users.FirstOrDefaultAsync(u => (u.Email ?? string.Empty).ToLower() == identifier.ToLower());
            else if (dto.LoginMethod?.ToLower() == "mobile")
                user = await _context.Users.FirstOrDefaultAsync(u => u.Mobile == identifier);
            else
                throw new Exception("Invalid login method. Use 'email' or 'mobile'.");

            if (user == null)
                throw new UnauthorizedAccessException("Invalid credentials. User not found");

            // ✅ Ensure both verifications done

            if (!user.IsVerified || !user.IsEmailVerified || !user.IsMobileVerified)
                throw new UnauthorizedAccessException("Email and mobile verification required before login");

            if (string.IsNullOrEmpty(user.Password))
                throw new Exception("User password not set. Please reset your password.");

            // ✅ Verify password (BCrypt)

            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(dto.Password, user.Password);

            if (!isPasswordValid)
                throw new UnauthorizedAccessException("Invalid password");

            // ✅ Generate JWT + Refresh token
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

            {
                // ❌ Log failed login attempt
                var failedActivity = new LoginActivity
                {
                    UserId = user.UserId,
                    IpAddress = ipAddress,
                    Status = "Failed",
                    LoginTime = DateTime.UtcNow
                };

                _context.LoginActivity.Add(failedActivity);
                await _context.SaveChangesAsync();

                // ✅ Record successful login activity
                var successActivity = new LoginActivity
                {
                    UserId = user.UserId,
                    IpAddress = ipAddress,
                    Status = "Success",
                    LoginMethod = dto.LoginMethod,
                    LoginTime = DateTime.UtcNow
                };
                _context.LoginActivity.Add(successActivity);
                await _context.SaveChangesAsync();

                // ✅ Token response with expiry info,Session expiry: 30 minutes of inactivity
                var accessExpiryMinutes = int.Parse(_config["JwtSettings:AccessTokenMinutes"] ?? "30");

                return new
                {
                    message = "Login successful",
                    accessToken = jwt,
                    refreshToken = refresh.Token,
                    expiresInSeconds = accessExpiryMinutes * 60,
                    userId = user.UserId,
                    name = user.Name,
                    email = user.Email
                };
            }
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

        public async Task RequestOtpAsync(string identifier)
        {
            // Example: find user by email or mobile
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.Email == identifier || u.Mobile == identifier);

            if (user == null)
                throw new Exception("User not found.");

            // Generate random OTP
            var otp = new Random().Next(100000, 999999).ToString();

            // Save to DB
            var otpEntry = new Otp
            {
                UserId = user.UserId,
                OtpCode = otp,
                CreatedAt = DateTime.UtcNow,
                ExpiryTime = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false
            };

            _context.Otp.Add(otpEntry);
            await _context.SaveChangesAsync();

            // Send OTP via email/SMS (example)
            Console.WriteLine($"OTP for {identifier}: {otp}");
        }


        public async Task VerifyOtpAsync(string identifier, string otp)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.Email == identifier || u.Mobile == identifier);

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


    }
}
