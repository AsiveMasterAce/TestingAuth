using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace RealCreate.Web.Controllers
{
    public class HandleCookieController : Controller
    {

        private static readonly AuthenticationProperties COOKIE_EXPIRES = new AuthenticationProperties()
        {
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            IsPersistent = true,
        };

        public class LoginModel
        {
            [Required(ErrorMessage = "Username is required")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password is required")]
            public string Password { get; set; }
        }

        [HttpGet("/auth/SignIn/")]
        public async Task<ActionResult> SignInPost(string claims)
        {
            // URL decode the claims string
            string decodedClaims = Uri.UnescapeDataString(claims);

            // Deserialize the claims
            var claimsList = JsonSerializer.Deserialize<List<Claim>>(decodedClaims);

            // Reconstruct the ClaimsIdentity
            var claimsIdentity = new ClaimsIdentity(claimsList, CookieAuthenticationDefaults.AuthenticationScheme);

            // Proceed with the authentication
            var authProperties = COOKIE_EXPIRES;
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                         new ClaimsPrincipal(claimsIdentity),
                                         authProperties);

            return Redirect("/");
        }

    }
}
