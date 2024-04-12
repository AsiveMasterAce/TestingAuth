namespace RealCreate.Web2.Services
{
    public interface ICookieAuthenticationService
    {
        Task SignInAsync(AuthenticatedUser user, bool isPersistent = false);
        Task SignOutAsync();
    }
}
