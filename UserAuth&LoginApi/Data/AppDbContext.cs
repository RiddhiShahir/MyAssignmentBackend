using Microsoft.EntityFrameworkCore;
using UserAuthLoginApi.Models;

namespace UserAuthLoginApi.Data
{
    public class AppDbContext : DbContext //sets up the connection string
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
        public DbSet<EmailVerification> EmailVerifications { get; set; }
        public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<Otp> Otp { get; set; }
        public DbSet<LoginActivity> LoginActivity { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);
                entity.Property(e => e.Email).IsRequired();
                entity.Property(e => e.Mobile).IsRequired();
                entity.HasIndex(e => e.Email).IsUnique();
                entity.HasIndex(e => e.Mobile).IsUnique();
                entity.Property(e => e.Name).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Password).IsRequired();
            });

            modelBuilder.Entity<Otp>(entity =>
            {
                entity.HasKey(e => e.OtpId);
                entity.Property(e => e.OtpCode).IsRequired();
                entity.Property(e => e.Mobile).IsRequired();

                entity.HasOne(e => e.User)
                      .WithMany(u => u.Otps)
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<LoginActivity>(entity =>
            {
                entity.HasKey(e => e.ActivityId);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.LoginTime).IsRequired();
                entity.Property(e => e.IpAddress).IsRequired();
                entity.Property(e => e.LoginMethod).IsRequired();
                entity.Property(e => e.Status).IsRequired();

                entity.HasOne(e => e.User)
                      .WithMany(u => u.LoginActivities)
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<PasswordResetToken>(entity =>
            {
                entity.HasOne(p => p.User)
                     .WithMany()
                     .HasForeignKey(p => p.UserId)
                     .OnDelete(DeleteBehavior.Cascade);

            });
        }
    }
}