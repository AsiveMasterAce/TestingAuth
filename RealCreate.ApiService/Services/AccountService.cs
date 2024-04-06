using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RealCreate.ApiService.Data;
using RealCreate.ApiService.Model;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RealCreate.ApiService.Services
{
    public class AccountService
    {
        private readonly ApplicationDBContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly JwtOptions _jwtOptions;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AccountService(ApplicationDBContext context, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, JwtOptions jwtOptions1, IHttpContextAccessor httpContext)
        { 
            _jwtOptions = jwtOptions1;
            _userManager = userManager; 
            _signInManager = signInManager;
            _context = context;
            _httpContextAccessor = httpContext;
        }

        public async Task<IActionResult> LogIn(UserModel model)
        {
            try
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    // Get the user from the database
                    var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == model.Email);


                    // Store the user ID in the session
                    _httpContextAccessor.HttpContext.Session.SetString("UserEmail", user.Email);
                    // Generate access token
                    var token = CreateAccessToken(_jwtOptions, user.UserName, TimeSpan.FromMinutes(30));

                    // Return the token in the response
                    return new OkObjectResult( new {token});
                }
                else
                {
                    return new BadRequestObjectResult("Invalid user creds");
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public async Task<IActionResult> Register(UserModel model)
        {
            try
            {

                var user = await _context.Users.Where(u => u.Email!.ToLower().Equals(model.Email!.ToLower())).FirstOrDefaultAsync();
                if (user != null)
                    return new BadRequestObjectResult("E-mail exists");

                var newUser = new AppUser
                {
                    Email = model.Email,
                    UserName = model.Email,
                };

                var result = await _userManager.CreateAsync(newUser, model.Password);
                    _context.SaveChanges();

                if (result.Succeeded)
                {

                  return new OkObjectResult("Registered Successfully");
                }
                else
                {
                    return new BadRequestObjectResult("Registration Failed");
                }
            }
            catch(Exception ex)
            {
                throw;
            }
        }
        static string CreateAccessToken(JwtOptions jwtOptions,string username,TimeSpan expiration)
        {
            var keyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);
            var symmetricKey = new SymmetricSecurityKey(keyBytes);

            var signingCredentials = new SigningCredentials(symmetricKey,SecurityAlgorithms.HmacSha256);

                    var claims = new List<Claim>()
                    {
                        new Claim("UserName", username),
                        new Claim("email", username),
                        new Claim("audience", jwtOptions.Audience)
                    };

            var token = new JwtSecurityToken(issuer: jwtOptions.Issuer,audience: jwtOptions.Audience,claims: claims,expires: DateTime.Now.Add(expiration),signingCredentials: signingCredentials);

            var rawToken = new JwtSecurityTokenHandler().WriteToken(token);
            return rawToken;
        }

        [Authorize]
        public async Task<IActionResult> CheckUserSession()
        {
            // Check if the session contains a user ID
            if (_httpContextAccessor.HttpContext.Session.TryGetValue("UserEmail", out var email))
            {
                // The user is authenticated
                // Retrieve the user from the database
                    var user = await _context.Users
                       .Where(x => x.Email == Encoding.UTF8.GetString(email))
                       .FirstOrDefaultAsync();

                if (user != null)
                {
                    // Process the request...
                    // For example, return the user's details

                    var authResponse = new AuthResponse
                    {
                        IsAuthenticated = true,
                        Username = user.UserName,
                    };
                    return new OkObjectResult(authResponse);
                }
                else
                {
                    // The user was not found in the database
                    return new BadRequestObjectResult("User not found");
                }
            }
            else
            {
                var authResponse = new AuthResponse
                {
                    IsAuthenticated = false,
                    Username = null,
                };
                // The user is not authenticated
                return new NotFoundObjectResult(authResponse);
            }                                                                                           
        }

    }
}
