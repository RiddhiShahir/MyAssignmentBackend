using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace UserAuthLoginApi.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordResetTokenTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LoginActivities_Users_UserId",
                table: "LoginActivities");

            migrationBuilder.DropPrimaryKey(
                name: "PK_LoginActivities",
                table: "LoginActivities");

            migrationBuilder.RenameTable(
                name: "LoginActivities",
                newName: "LoginActivity");

            migrationBuilder.RenameColumn(
                name: "Email",
                table: "LoginActivity",
                newName: "DeviceId");

            migrationBuilder.RenameColumn(
                name: "Id",
                table: "LoginActivity",
                newName: "ActivityId");

            migrationBuilder.RenameIndex(
                name: "IX_LoginActivities_UserId",
                table: "LoginActivity",
                newName: "IX_LoginActivity_UserId");

            migrationBuilder.AlterColumn<string>(
                name: "IpAddress",
                table: "LoginActivity",
                type: "text",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LoginMethod",
                table: "LoginActivity",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Status",
                table: "LoginActivity",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_LoginActivity",
                table: "LoginActivity",
                column: "ActivityId");

            migrationBuilder.CreateTable(
                name: "PasswordResetTokens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    UserId = table.Column<int>(type: "integer", nullable: false),
                    Token = table.Column<string>(type: "text", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordResetTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordResetTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UserId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetTokens_UserId",
                table: "PasswordResetTokens",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_LoginActivity_Users_UserId",
                table: "LoginActivity",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LoginActivity_Users_UserId",
                table: "LoginActivity");

            migrationBuilder.DropTable(
                name: "PasswordResetTokens");

            migrationBuilder.DropPrimaryKey(
                name: "PK_LoginActivity",
                table: "LoginActivity");

            migrationBuilder.DropColumn(
                name: "LoginMethod",
                table: "LoginActivity");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "LoginActivity");

            migrationBuilder.RenameTable(
                name: "LoginActivity",
                newName: "LoginActivities");

            migrationBuilder.RenameColumn(
                name: "DeviceId",
                table: "LoginActivities",
                newName: "Email");

            migrationBuilder.RenameColumn(
                name: "ActivityId",
                table: "LoginActivities",
                newName: "Id");

            migrationBuilder.RenameIndex(
                name: "IX_LoginActivity_UserId",
                table: "LoginActivities",
                newName: "IX_LoginActivities_UserId");

            migrationBuilder.AlterColumn<string>(
                name: "IpAddress",
                table: "LoginActivities",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AddPrimaryKey(
                name: "PK_LoginActivities",
                table: "LoginActivities",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_LoginActivities_Users_UserId",
                table: "LoginActivities",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
