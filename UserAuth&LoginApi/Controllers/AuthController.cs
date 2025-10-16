using Microsoft.AspNetCore.Mvc;
using UserAuthLoginApi.Models.DTOs;
using UserAuthLoginApi.Services;
using UserAuthLoginApi.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace UserAuthLoginApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly AppDbContext _context; // ✅ Added to fetch user status

        public AuthController(AuthService authService, AppDbContext context)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _context = context;
        }

        // --- User Registration ---
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
        {
            try
            {
                if (request == null)
                    return BadRequest(new { error = "Invalid registration data" });

                var origin = $"{Request.Scheme}://{Request.Host}";

                // Call actual registration logic:

                var result = await _authService.Register(request.Name, request.Email, request.Mobile, request.Password);

                var newUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email && u.Mobile == request.Mobile);
                return Ok(new
                {
                    message = "Registration successful. Check email and SMS for verification.",
                    userId = newUser?.UserId,
                    result
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
            }
        }

        // --- Verify Email ---
        [HttpPost("verifyemail")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
        {
            try
            {
                if (request == null)
                    return BadRequest(new { error = "Invalid verification data" });

                await _authService.VerifyEmail(request.UserId, request.Token);

                var user = await _context.Users.FindAsync(request.UserId);
                if (user == null)
                    return NotFound(new { error = "User not found" });

                // ✅ Smart response based on verification status
                if (user.IsVerified)
                {
                    return Ok(new
                    {
                        message = "Email verified and account activated successfully.",
                        status = "Active"
                    });
                }

                return Ok(new
                {
                    message = "Email verified successfully.Please verify your mobile number to activate your account.",
                    status = "Pending"
                });

            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
            }
        }

        // --- Verify OTP ---
        [HttpPost("verifyotp")]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
        {
            try
            {
                if (request == null)
                    return BadRequest(new { error = "Invalid OTP data" });

                await _authService.VerifyOtp(request.UserId, request.Otp);

                var user = await _context.Users.FindAsync(request.UserId);
                if (user == null)
                    return NotFound(new { error = "User not found" });

                // ✅ Smart response based on verification status
                if (user.IsVerified)
                {
                    return Ok(new
                    {
                        message = "Mobile verified and account activated successfully.",
                        status = "Active"
                    });
                }

                return Ok(new
                {
                    message = "Mobile verified successfully. Please verify your email to activate your account.",
                    status = "Pending"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
            }
        }

        // --- User Login ---

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto request)
        {
            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var response = await _authService.LoginAsync(request, ipAddress);
                return Ok(response);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
            }

        }

        // ---------------- FORGOT PASSWORD ----------------

        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            try
            {
                await _authService.ForgotPasswordAsync(dto.email);
                return Ok(new { message = "Password reset token sent to your email." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        // ---------------- RESET PASSWORD (VIA TOKEN)----------------

        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            try
            {
                await _authService.ResetPasswordAsync(dto);
                return Ok(new { message = "Password reset successfully." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        // ---------------- CHANGE PASSWORD (logged in user) ----------------

        [Authorize]  // Requires logged-in user
        [HttpPost("changepassword")]
        // public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        // {
        //     var userEmail = User.Identity?.Name; // Extract From JWT
        //     if (userEmail == null)
        //         return Unauthorized(new { message = "User not authenticated." });

        //     try
        //     {
        //         var userId = int.Parse(User.FindFirst("id")!.Value);
        //         await _authService.ChangePasswordAsync(userId, dto.CurrentPassword, dto.NewPassword);
        //         return Ok(new { message = "Password changed successfully." });
        //     }
        //     catch (Exception ex)
        //     {
        //         return BadRequest(new { error = ex.Message });
        //     }
        // }
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var userEmail = User.Identity?.Name; // Extract from JWT
            if (string.IsNullOrEmpty(userEmail))
                return Unauthorized(new { message = "Invalid or missing token" });

            var result = await _authService.ChangePasswordAsync(userEmail, dto.CurrentPassword, dto.NewPassword);

            if (!result.Success)
                return BadRequest(new { message = result.Message });

            return Ok(new { message = "Password updated successfully" });
        }

        // ---------------- RESEND OTP ----------------

        [HttpPost("requestotp")]
        public async Task<IActionResult> RequestOtp([FromBody] RequestOtpDto request)
        {
            try
            {
                await _authService.RequestOtpAsync(request.Mobile);
                return Ok(new { message = "OTP sent successfully." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        // ---------------- RESEND EMAIL TOKEN ----------------

        [HttpPost("requesttoken")]
        public async Task<IActionResult> RequestToken([FromBody] RequestTokenDto request)
        {
            // var email = request.email;
            // if (string.IsNullOrWhiteSpace(email))
            //     return BadRequest(new { error = "Email is required" });

            // // Check if user exists
            // try
            // {
            //     var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            //     if (user == null) return NotFound(new { error = "User not found" });

            //     // Reuse token generation logic
            //     var emailToken = Guid.NewGuid().ToString();

            //     // Reuse sending logic

            //     return Ok(new { message = "Verification email resent." });
            // }

            try
            {
                await _authService.RequestTokenAsync(request.email);
                return Ok(new { message = "Verification email resent." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        // // --- Set Password ---
        // [HttpPost("setpassword")]
        // public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
        // {
        //     try
        //     {
        //         if (string.IsNullOrWhiteSpace(request.Password))
        //             return BadRequest(new { error = "Password cannot be empty" });

        //         var user = await _context.Users.FindAsync(request.UserId);
        //         if (user == null)
        //             return NotFound(new { error = "User not found" });

        //         return Ok(new
        //         {
        //             message = "Password set successfully.",
        //             verified = user.IsVerified
        //         });
        //     }
        //     catch (Exception ex)
        //     {
        //         return BadRequest(new { error = ex.Message });
        //     }
        // }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var result = await _authService.RefreshTokenAsync(request.RefreshToken, ipAddress);
                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("validate-token")]
        [Authorize]
        public async Task<IActionResult> ValidateToken()
        {
            try
            {
                var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                var isValid = await _authService.ValidateTokenAsync(token);
                if (!isValid)
                    return Unauthorized(new { error = "Invalid or expired token" });

                return Ok(new { message = "Token is valid" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var email = User.Identity?.Name; // Extracted from JWT
            if (string.IsNullOrEmpty(email))
                return Unauthorized(new { message = "Invalid or missing token" });

            var user = await _context.Users
                .Where(u => u.Email == email)
                .Select(u => new
                {
                    Id = u.UserId,
                    name = u.Name,
                    email = u.Email,
                    mobile = u.Mobile,
                    CreatedAt = u.CreatedDate
                })
                .FirstOrDefaultAsync();

            if (user == null)
                return NotFound(new { message = "User not found" });

            return Ok(user);
        }

        [Authorize]
        [HttpPut("updateprofile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDto dto)
        {
            var email = User.Identity?.Name;
            if (email == null)
                return Unauthorized(new { message = "Invalid or missing token" });

            var success = await _authService.UpdateUserProfileAsync(email, dto);
            if (!success)
                return NotFound(new { message = "User not found" });

            return Ok(new { message = "Profile updated successfully" });
        }


    }

    // --- DTOs for requests ---
    public class RegistrationRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Mobile { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class VerifyEmailRequest
    {
        public int UserId { get; set; }
        public string Token { get; set; } = string.Empty;
    }

    public class VerifyOtpRequest
    {
        public int UserId { get; set; }
        public string Otp { get; set; } = string.Empty;
    }

    public class SetPasswordRequest
    {
        public int UserId { get; set; }
        public string Password { get; set; } = string.Empty;
    }
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }

    public class RequestTokenDto
    {
        public string email { get; set; } = string.Empty; // email or mobile
    }

    public class RequestOtpDto
    {
        public string Mobile { get; set; } = string.Empty;
    }

}
