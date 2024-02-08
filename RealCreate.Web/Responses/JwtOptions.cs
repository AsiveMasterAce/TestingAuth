namespace RealCreate.Web.Responses
{
    public record class JwtOptions(string Issuer, string Audience, string SigningKey, int ExpirationSeconds);
}
