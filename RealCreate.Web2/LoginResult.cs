namespace RealCreate.Web2
{
    public record LoginResult(string? Token, string? RefreshToken, DateTime? RefreshTokenExpiryTime);

    public static class Constants
    {
        public const string AuthCookieToken = "Token";
    }
    public class LoginRequest
    {
        public required string Email { get; set; } = string.Empty;
        public required string Password { get; set; } = string.Empty;
    }
}
