using Microsoft.AspNetCore.Mvc;
using UserAuthLoginApi.Models.DTOs;
using UserAuthLoginApi.Services;
using UserAuthLoginApi.Data;
using Microsoft.EntityFrameworkCore;

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

                // return Ok(new
                // {
                //     message = "Registration successful. Check email and SMS for verification.",
                //     // originUsed = origin
                //     result
                // });

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

        // --- Set Password ---
        [HttpPost("setpassword")]
        public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Password))
                    return BadRequest(new { error = "Password cannot be empty" });

                var user = await _context.Users.FindAsync(request.UserId);
                if (user == null)
                    return NotFound(new { error = "User not found" });

                return Ok(new
                {
                    message = "Password set successfully.",
                    verified = user.IsVerified
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }


        // --- Refresh Token ---

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var result = await _authService.RefreshTokenAsync(request.RefreshToken, ipAddress);

                if (result == null)
                    return Unauthorized(new { error = "Invalid or expired refresh token" });

                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
            }
        }
        // [HttpPost("refresh")]
        // public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
        // {
        //     try
        //     {
        //         var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        //         var response = await _authService.RefreshTokenAsync(refreshToken, ipAddress);
        //         return Ok(response);
        //     }
        //     catch (Exception ex)
        //     {
        //         return BadRequest(new { error = ex.Message, details = ex.InnerException?.Message });
        //     }
        // }

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

        [HttpPost("resendemail")]
        public async Task<IActionResult> ResendEmail([FromBody] string email)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null) return NotFound(new { error = "User not found" });

                // Reuse token generation logic
                var emailToken = Guid.NewGuid().ToString();
             
                // Reuse sending logic

                return Ok(new { message = "Verification email resent." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
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
}
