using Microsoft.AspNetCore.Components.Authorization;
using RealCreate.Web.Services;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Transactions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Blazored.SessionStorage;
using Microsoft.AspNetCore.Authentication;

namespace RealCreate.Web.AuthProviders
{
    public class UserAuthenticationService : AuthenticationStateProvider
    {
        private readonly LocalStorageService _localStorage;
        private readonly ISessionStorageService _SessionStorage;


        public UserAuthenticationService(LocalStorageService localStorage, ISessionStorageService session)
        {
            _localStorage = localStorage;
            _SessionStorage = session;
        }
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            string token = await _SessionStorage.GetItemAsync<string>("authToken");

            if (string.IsNullOrEmpty(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            HttpContextAccessor httpContextAccessor = new HttpContextAccessor();

            var identity = GetIdentityFromToken(token);
            var principal = new ClaimsPrincipal(identity);
            if (httpContextAccessor.HttpContext != null && httpContextAccessor.HttpContext.User.Identity.IsAuthenticated)
            {
                identity = (ClaimsIdentity)httpContextAccessor.HttpContext.User.Identity;
                principal = new ClaimsPrincipal(identity);
            }
            return await Task.FromResult(new AuthenticationState(principal));

        }

        public ClaimsIdentity GetIdentityFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            var claims = jwtSecurityToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();
            return new ClaimsIdentity(claims, "jwt");
        } 
        public IEnumerable<Claim> GetIdentityFromTokenList(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            var claims = jwtSecurityToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();
            return claims;
        }

        public void AuthenticateUser(string token)
        {
            var identity = GetIdentityFromToken(token);
            var user = new ClaimsPrincipal(identity);
            var state = new AuthenticationState(user);
            NotifyAuthenticationStateChanged(Task.FromResult(state));

            //HttpContextAccessor httpContextAccessor = new HttpContextAccessor();
            //httpContextAccessor.HttpContext.SignInAsync()
        }
        public async Task AuthenticateUserAsync()
        {
            var token = await _SessionStorage.GetItemAsync<string>("authToken");
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
    public class CookieValidator
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IServiceScopeFactory _serviceScopeFactory;

        private JwtSecurityTokenHandler tokenHandler = new();
        private SigningCredentials TokenCred;
        private SecurityKey SecurityKey;

        private SecurityToken? token;
        public CookieValidator(IHttpContextAccessor context, IServiceScopeFactory factory)
        {
            _httpContextAccessor = context;
             _serviceScopeFactory = factory;

            TokenCred = new SigningCredentials(new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("ServerSecurityKey")), SecurityAlgorithms.HmacSha256Signature);
            SecurityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("ServerSecurityKey"));
        }

        public bool ValidateToken(string jwt)
        {
            try
            {

                tokenHandler.ValidateToken(jwt, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "NameOfYourAPIService",
                    IssuerSigningKey = SecurityKey,
                    ValidAudiences = new List<string>
                    {
                        "https://localhost","",""
                    },
                    ValidateLifetime = true,
                }, out token);

                var claims = tokenHandler.ReadJwtToken(jwt).Claims;

                return true;
            }
            catch
            {
                return false;
            }
        }

    }
    public class JwtMiddleWare
    {
        private readonly RequestDelegate _next;
        private readonly CookieValidator cookieValidator;
        public JwtMiddleWare(RequestDelegate _next, CookieValidator _validate)
        {
            this._next = _next;
            this.cookieValidator = _validate;
        }
        public async Task Invoke(HttpContext context)
        {
            var cookieName = "";
            var cookie = context.Request.Cookies[cookieName];
            if (cookieValidator.ValidateToken(cookie))
            {
                //Assign Claims Context.User.Claims
                //var ClaimsIdentity = new ClaimsIdentity()
                //context.User.AddIdentity();
                context.Items["User"] = cookie;
            }
        }
    }
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var allowAnonymous = context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any();
            if(allowAnonymous)
            {
                return;
            }

            var token = (string)context.HttpContext.Items["User"];
            if (String.IsNullOrEmpty(token))
            {
                context.Result = new UnauthorizedResult();
            }
        }
    }

}
