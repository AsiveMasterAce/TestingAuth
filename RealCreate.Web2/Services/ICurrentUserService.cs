namespace RealCreate.Web2.Services
{
    public interface ICurrentUserService
    {
        bool IsAuthenticated();
        string GetUserId();
        string GetUserName();
        AuthenticatedUser? GetAuthenticatedUser();
    }
}
