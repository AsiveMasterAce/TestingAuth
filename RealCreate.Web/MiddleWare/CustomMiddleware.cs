namespace RealCreate.Web.MiddleWare
{
    public class CustomMiddleware
    {
        private readonly RequestDelegate _next;

        public CustomMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Add your logic here to set cookies or headers
            // For example, setting a cookie
            context.Response.Cookies.Append("RealCreate", "jwts", new CookieOptions { Expires = DateTimeOffset.UtcNow.AddMinutes(10) });

            // Call the next middleware in the pipeline
            await _next(context);
        }
    }
}
