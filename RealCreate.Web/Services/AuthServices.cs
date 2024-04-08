using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
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

                var claimsIdentity = new ClaimsIdentity(claims);

                var authProperties = COOKIE_EXPIRES;

                // Set a callback to set the cookie before the response starts
                _contextAccessor.HttpContext.Response.OnStarting(state =>
                {
                    var context = (HttpContext)state;
                    context.Response.Cookies.Append("RealCreate", "jwts", new CookieOptions { Expires = DateTimeOffset.UtcNow.AddMinutes(10) });
                    return Task.CompletedTask;
                }, _contextAccessor.HttpContext);

                await _contextAccessor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                              new ClaimsPrincipal(claimsIdentity),
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
