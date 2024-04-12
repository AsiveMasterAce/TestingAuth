
using Blazored.SessionStorage;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.IdentityModel.Tokens;
using RealCreate.Web;
using RealCreate.Web.AuthProviders;
using RealCreate.Web.Components;
using RealCreate.Web.MiddleWare;
using RealCreate.Web.Responses;
using RealCreate.Web.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();
builder.Services.AddAuthentication();
// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddOutputCache();
//builder.Services.AddServerSideBlazor()
//    .AddCircuitOptions(options => { options.DetailedErrors = true; })
//    .AddInteractiveServerComponents();
builder.Services.AddHttpContextAccessor();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "RealCreate";
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

//builder.Services.AddScoped<AuthenticationStateProvider, PersistingServerAuthenticationStateProvider>();
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
builder.Services.AddBlazoredSessionStorage();

builder.Services.AddScoped<IHostEnvironmentAuthenticationStateProvider>(o =>
                (ServerAuthenticationStateProvider)
                o.GetRequiredService<AuthenticationStateProvider>());

//builder.Services.AddAuthentication(IISDefaults.AuthenticationScheme);
builder.Services.AddScoped<UserAuthenticationService>();
builder.Services.AddScoped<CookieAuthStateProvider>();
builder.Services.AddScoped<AuthServices>();
builder.Services.AddScoped<LocalStorageService>();
builder.Services.AddHttpClient<WeatherApiClient>(client=> client.BaseAddress = new("http://apiservice"));
//var jwtOptions = builder.Configuration.GetSection("JwtOptions").Get<JwtOptions>();

//builder.Services.AddSingleton(jwtOptions);
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseMiddleware<CustomMiddleware>();
app.UseAuthorization();
app.UseAuthentication();
app.UseStaticFiles();

app.UseAntiforgery();

app.UseOutputCache();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
    
app.MapDefaultEndpoints();
app.MapControllers();

app.Run();
