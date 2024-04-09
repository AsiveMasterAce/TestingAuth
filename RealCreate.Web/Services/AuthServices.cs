using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RealCreate.Web.Services
{
    public class AuthServices
    {

        private readonly IHttpContextAccessor _contextAccessor;
        public AuthServices(IHttpContextAccessor httpContext) { 
        
            _contextAccessor = httpContext;
        }

        private AuthenticationState _authState;
        public event Action OnChange;
        public AuthenticationState AuthState
        {
            get => _authState;
            set
            {
                _authState = value;
                NotifyStateChanged();
            }
        }

        private void NotifyStateChanged() => OnChange?.Invoke();

        public void AddHeaders()
        {
            if (!_contextAccessor.HttpContext.Response.HasStarted)
            {
                _contextAccessor.HttpContext.Response.OnStarting(state =>
                {
                    var context = (HttpContext)state;
                    context.Response.Cookies.Append("RealCreate", "jwts", new CookieOptions { Expires = DateTimeOffset.UtcNow.AddMinutes(10) });
                    return Task.CompletedTask;
                }, _contextAccessor.HttpContext);
            }
            else
            {
                // Handle the case where the response has already started
                // This might involve logging an error or throwing an exception
            }
        }
        public void AuthenticateUser(string token)
        {
            var identity = GetIdentityFromToken(token);
            var user = new ClaimsPrincipal(identity);
            var state = new AuthenticationState(user);

            _contextAccessor.HttpContext.User = user;

        }
        public ClaimsIdentity GetIdentityFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            var claims = jwtSecurityToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();
            return new ClaimsIdentity(claims, "jwt");
        }
        public async void SignInPost(ClaimsIdentity claims)
        {
            try
            {
                _contextAccessor.HttpContext.Response.HasStarted.Equals(false);

              
                
                    var authProperties = COOKIE_EXPIRES;
                    await _contextAccessor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                  new ClaimsPrincipal(claims),
                                                  authProperties);
                
            }
            
            catch (Exception ex)
            {

            }
        }

        private static readonly AuthenticationProperties COOKIE_EXPIRES = new AuthenticationProperties()
        {
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            IsPersistent = true,
        };
    }
}
