using Microsoft.AspNetCore.Mvc.Filters;

namespace RealCreate.Web.MiddleWare
{
    public class CustomActionFilter: IActionFilter
    {
        public void OnActionExecuting(ActionExecutingContext context)
        {
            // Add your logic here to set cookies or headers
            // For example, setting a cookie
            context.HttpContext.Response.Cookies.Append("RealCreate", "jwts", new CookieOptions { Expires = DateTimeOffset.UtcNow.AddMinutes(10) });
        }

        public void OnActionExecuted(ActionExecutedContext context)
        {
            // No action needed here
        }
    }
}
