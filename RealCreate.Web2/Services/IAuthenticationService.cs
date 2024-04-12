namespace RealCreate.Web2.Services
{
    public interface IAuthenticationService
    {
        Task<LoginResult> LoginAsync(string email, string password);
        Task LogoutAsync();
    }
}
