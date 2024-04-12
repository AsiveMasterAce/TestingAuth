using Microsoft.VisualBasic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RealCreate.Web2.Services
{
    public class AuthenticationService: IAuthenticationService
    {
        private readonly ICookieService _cookieService;
        private readonly ICookieAuthenticationService _cookieAuthenticationService;
        private readonly ApiClient _apiClient;

        public AuthenticationService(ICookieAuthenticationService cookieAuthenticationService,
            ICookieService cookieService,ApiClient apiClient)
        {
            _cookieAuthenticationService = cookieAuthenticationService;
            _cookieService = cookieService;
            _apiClient = apiClient;
        }

        public async Task<LoginResult> LoginAsync(string email, string password)
        {
            // Authenticate the user
            var user = await _apiClient.LoginAsync(email, password);

            // If the user is authenticated, sign them in
            _cookieService.Set(key: Constants.AuthCookieToken, value: user.Token);

            var autheduser = JwtParser.ParseJwt(user.Token);

            await _cookieAuthenticationService.SignInAsync(autheduser);

            return user;
        }

        public async Task LogoutAsync()
        {
            await _cookieAuthenticationService.SignOutAsync();
        }
      
    }
    public static class JwtParser
    {
        public static AuthenticatedUser ParseJwt(string userToken)
        {
            var securityToken = new JwtSecurityTokenHandler().ReadJwtToken(userToken);

            var userName = securityToken.Claims.First(claim => claim.Type == "Username").Value;
            var emails = securityToken.Claims.First(claim => claim.Type == "Email").Value;


            var user = new AuthenticatedUser
            {
                Username = userName,
                Email = emails,
            };

            return user;
        }
    }
}
