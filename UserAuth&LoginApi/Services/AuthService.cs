using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using UserAuthLoginApi.Data;
using UserAuthLoginApi.Models;
using UserAuthLoginApi.Models.DTOs;

namespace UserAuthLoginApi.Services
{
    public interface IAuthService
    {
        Task RegisterAsync(RegisterRequest dto, string origin);
        Task<bool> VerifyEmailAsync(string token);
        Task RequestOtpAsync(string mobile);
        Task<bool> VerifyOtpAsync(string mobile, string otp);
        Task<TokenResponseDto> LoginAsync(LoginDto dto, string ipAddress);
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

    public class AuthService
    {
        private readonly AppDbContext _context;
        private readonly IEmailService _emailService;
        private readonly ISmsService _smsService;
        private readonly IConfiguration _config;
        private readonly PasswordHasher<User> _passwordHasher;

        public AuthService(AppDbContext context, IEmailService emailService, ISmsService smsService, IConfiguration config)
        {
            _context = context;
            _emailService = emailService;
            _smsService = smsService;
            _config = config;
            _passwordHasher = new PasswordHasher<User>();
        }

        public async Task<string> Register(string name, string email, string mobile, string password)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(mobile))
                throw new ArgumentException("Name, email, and mobile cannot be empty.");

            if (_context.Users.Any(u => u.Email == email || u.Mobile == mobile))
                throw new Exception("Duplicate email or mobile");

            var user = new User
            {
                Name = name,
                Email = email,
                Mobile = mobile,
                Password = BCrypt.Net.BCrypt.HashPassword(password)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // ✅ Generate and store email verification token
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


            // Generate and save email verification token public async Task<string> GenerateEmailVerificationTokenAsync(User user) { var token = Guid.NewGuid().ToString(); // You can use any secure token generator var emailVerification = new EmailVerification { UserId = userId, Token = token, Email = email, ExpiresAt = DateTime.UtcNow.AddMinutes(10) }; _context.EmailVerificationTokens.Add(emailVerification); await _context.SaveChangesAsync(); return token; }

            // Generate and send OTP for mobile
            var otp = GenerateOtp();
            await _smsService.SendOtp(mobile, otp);

            // Store hashed OTP in OTP table 
            try
            {
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
                var result = await _context.SaveChangesAsync();
                Console.WriteLine($"✅ OTP save result: {result} rows affected");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error saving OTP: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"   Inner Exception: {ex.InnerException.Message}");
            }
            return "Verification sent";
        }

        public async Task VerifyEmail(int userId, string token)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("Invalid user ID");

            // ✅ Find the email verification token in DB
            var verification = await _context.EmailVerifications
                .Where(e => e.UserId == userId && e.Token == token && !e.IsUsed)
                .OrderByDescending(e => e.CreatedAt)
                .FirstOrDefaultAsync();

            if (verification == null)
                throw new Exception("Invalid or expired token");

            // ✅ Check expiry
            if (DateTime.UtcNow > verification.ExpiresAt)
                throw new Exception("Verification link has expired");

            // ✅ Mark token as used
            verification.IsUsed = true;

            // ✅ Update user
            user.IsEmailVerified = true;

            // ✅ Auto-set IsVerified if both verifications are done
            if (user.IsEmailVerified && user.IsMobileVerified)
                user.IsVerified = true;

            await _context.SaveChangesAsync();
        }

        public async Task VerifyOtp(int userId, string otp)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("Invalid user ID");

            // OTP validation logic goes here
            // Find the OTP entry for the given user
            var otpEntry = await _context.Otp
                .Where(o => o.UserId == userId && o.OtpCode == otp && !o.IsUsed)
                .OrderByDescending(o => o.CreatedAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null)
                throw new Exception("Invalid or expired OTP");

            // Check if the OTP is expired
            if (DateTime.UtcNow > otpEntry.ExpiryTime)
                throw new Exception("OTP has expired");

            // ✅ Mark OTP as used
            otpEntry.IsUsed = true;

            // ✅ Mark user's mobile as verified
            user.IsMobileVerified = true;

            // Auto-set IsVerified if both email & mobile are verified
            if (user.IsEmailVerified && user.IsMobileVerified)
                user.IsVerified = true;

            otpEntry.IsUsed = true;
            otpEntry.UsedAt = DateTime.UtcNow;

            // ✅ Save both updates together
            await _context.SaveChangesAsync();
        }

        public async Task SetPassword(int userId, string password)
        {
            if (!IsStrongPassword(password))
                throw new Exception("Weak password");

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new Exception("User not found");

            user.Password = BCrypt.Net.BCrypt.HashPassword(password);
            user.IsVerified = true;
            user.LastUpdatedDate = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }

        private bool IsStrongPassword(string pw)
        {
            var regex = new System.Text.RegularExpressions.Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$");
            return regex.IsMatch(pw);
        }

        private string GenerateOtp() => new Random().Next(100000, 999999).ToString();

        public async Task<TokenResponseDto> LoginAsync(LoginDto dto, string ipAddress)
        {
            var identifier = dto.Identifier.Trim();
            User? user = null;

            if (identifier.Contains("@"))
                user = await _context.Users.FirstOrDefaultAsync(u => u.Email == identifier.ToLower());
            else
                user = await _context.Users.FirstOrDefaultAsync(u => u.Mobile == identifier);

            if (user == null)
                throw new UnauthorizedAccessException("Invalid credentials");

            if (string.IsNullOrEmpty(user.Password))
                throw new UnauthorizedAccessException("Invalid credentials");

            var verify = _passwordHasher.VerifyHashedPassword(user, user.Password, dto.Password);
            if (verify == PasswordVerificationResult.Failed)
                throw new UnauthorizedAccessException("Invalid credentials");

            if (!user.IsEmailVerified || !user.IsMobileVerified)
                throw new UnauthorizedAccessException("Email or mobile not verified");

            var jwt = CreateJwtToken(user);
            var refresh = new RefreshToken
            {
                UserId = user.UserId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_config["JwtSettings:RefreshTokenDays"] ?? "30")),
                CreatedByIp = ipAddress
            };

            _context.RefreshTokens.Add(refresh);
            await _context.SaveChangesAsync();

            return new TokenResponseDto
            {
                AccessToken = jwt,
                RefreshToken = refresh.Token,
                ExpiresInSeconds = int.Parse(_config["JwtSettings:AccessTokenMinutes"] ?? "15") * 60
            };
        }

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
                ExpiresInSeconds = int.Parse(_config["JwtSettings:AccessTokenMinutes"] ?? "15") * 60
            };
        }

        private string CreateJwtToken(User user)
        {
            var jwtSettings = _config.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["AccessTokenMinutes"] ?? "15"));

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
    }
}
