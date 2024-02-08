using Microsoft.AspNetCore.Components.Authorization;
using RealCreate.Web.Services;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace RealCreate.Web.AuthProviders
{
    public class UserAuthenticationService : AuthenticationStateProvider
    {
        private readonly LocalStorageService _localStorage;

        public UserAuthenticationService(LocalStorageService localStorage)
        {
            _localStorage = localStorage;
        }
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            string token = await _localStorage.GetItemAsync("authToken");

            if (string.IsNullOrEmpty(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }
            else
            {
                var identity = string.IsNullOrEmpty(token) ? new ClaimsIdentity() : GetIdentityFromToken(token);
                var user = new ClaimsPrincipal(identity);
                return await Task.FromResult(new  AuthenticationState(user));
            }
        }

        private ClaimsIdentity GetIdentityFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            var claims = jwtSecurityToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();
            return new ClaimsIdentity(claims, "jwt");
        }


        public async Task AuthenticateUserAsync()
        {
            var token = await _localStorage.GetItemAsync("authToken");
            if (!string.IsNullOrEmpty(token))
            {
                var identity = GetIdentityFromToken(token);

                var principal = new ClaimsPrincipal(identity);
                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
            }
        }

        public async Task RefreshTokenAsync()
        {
            // Implement the logic to refresh the token
        }

        public async Task LogOutAsync()
        {
            await _localStorage.RemoveItemAsync("authToken");
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
        }
    }


}
