
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
builder.Services.AddServerSideBlazor()
    .AddCircuitOptions(options => { options.DetailedErrors = true; })
    .AddInteractiveServerComponents();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/logIn";
        options.Cookie.Name = "RealCreate";

        options.ExpireTimeSpan = TimeSpan.FromMinutes(2);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;

        //options.Events.OnSignedIn = context => {
        //    var httpContext = context.HttpContext;
        //    httpContext.Items["Properties"] = context.Properties;
        //    httpContext.Features.Set(context.Properties);
        //    return Task.CompletedTask;
        //};
    });


builder.Services.AddScoped<UserAuthenticationService>();
builder.Services.AddScoped<LocalStorageService>();
builder.Services.AddHttpClient<WeatherApiClient>(client=> client.BaseAddress = new("http://apiservice"));
//var jwtOptions = builder.Configuration.GetSection("JwtOptions").Get<JwtOptions>();

//builder.Services.AddSingleton(jwtOptions);
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
