
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.IdentityModel.Tokens;
using RealCreate.Web;
using RealCreate.Web.AuthProviders;
using RealCreate.Web.Components;
using RealCreate.Web.Responses;
using RealCreate.Web.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication();
builder.Services.AddAuthorization();
builder.Services.AddOutputCache();
builder.Services.AddAuthorizationCore(options =>
{
    options.AddPolicy("MyPolicy", policy =>
        policy.RequireAuthenticatedUser());
});

builder.Services.AddScoped<AuthenticationStateProvider, UserAuthenticationService>();
builder.Services.AddScoped<LocalStorageService>();
builder.Services.AddHttpClient<WeatherApiClient>(client=> client.BaseAddress = new("http://apiservice"));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme) // Use CookieAuthenticationDefaults.AuthenticationScheme as the default scheme
       .AddCookie();
var jwtOptions = builder.Configuration.GetSection("JwtOptions").Get<JwtOptions>();

builder.Services.AddSingleton(jwtOptions);
builder.Services.AddAuthorizationBuilder();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        //convert the string signing key to byte array
        byte[] signingKeyBytes = Encoding.UTF8
            .GetBytes(jwtOptions.SigningKey);

        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
        };
    });
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();

app.UseAntiforgery();

app.UseOutputCache();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
    
app.MapDefaultEndpoints();

app.Run();
