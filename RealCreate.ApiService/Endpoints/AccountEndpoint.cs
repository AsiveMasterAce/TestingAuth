using Microsoft.AspNetCore.Mvc;
using RealCreate.ApiService.Model;
using RealCreate.ApiService.Services;
using System.Net;

namespace RealCreate.ApiService.Endpoints
{
    public static class AccountEndpoint
    {

        public static IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoint)
        {

            var group = endpoint.MapGroup("api/account/");
            group.MapPost("LogIn",Login);
            group.MapPost("register",Register);
            group.MapGet("IsAuthenticated", IsAuthenticated);
            return endpoint;
        }

        private static async Task Login([FromBody] UserModel model, HttpResponse response, [FromServices]AccountService _service)
        {
            try
            {
                var actionResult = await _service.LogIn(model);

                if (actionResult is BadRequestObjectResult badRequest)
                {
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await response.WriteAsJsonAsync(badRequest.Value);
                }
                else if (actionResult is OkObjectResult ok)
                {
                    response.StatusCode = (int)HttpStatusCode.OK;
                    await response.WriteAsJsonAsync(ok.Value);
                }

            }
            catch(Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await response.WriteAsJsonAsync(ex.Message);
            }

        }

        private static async Task Register([FromBody] UserModel model, HttpResponse response, [FromServices] AccountService _service)
        {
            try
            {
                var actionResult = await _service.Register(model);

                if (actionResult is BadRequestObjectResult badRequest)
                {
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await response.WriteAsJsonAsync(badRequest.Value);
                }
                else if (actionResult is OkObjectResult ok)
                {
                    response.StatusCode = (int)HttpStatusCode.OK;
                    await response.WriteAsJsonAsync(ok.Value);
                }

            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await response.WriteAsJsonAsync(ex.Message);
            }


        }

        private static async Task IsAuthenticated(HttpResponse response, [FromServices] AccountService _service, HttpContext _httpContext)
        {
            try
            {
                var actionResult = await _service.CheckUserSession();
                //// Check if the session contains a user ID
                //if (_httpContext.Session.TryGetValue("userId", out var userId))
                //{
                //    // The user is authenticated
                //    response.StatusCode = (int)HttpStatusCode.OK;
                //    await response.WriteAsJsonAsync(new { IsAuthenticated = true });
                //}
                //else
                //{
                //    // The user is not authenticated
                //    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                //    await response.WriteAsJsonAsync(new { IsAuthenticated = false });
                //}
                if (actionResult is BadRequestObjectResult badRequest)
                {
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await response.WriteAsJsonAsync(badRequest.Value);
                }
                else if (actionResult is OkObjectResult ok)
                {
                    response.StatusCode = (int)HttpStatusCode.OK;
                    await response.WriteAsJsonAsync(ok.Value);
                }
                else if (actionResult is NotFoundObjectResult notFound)
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    await response.WriteAsJsonAsync(notFound.Value);
                }

            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                await response.WriteAsJsonAsync(new { Error = ex.Message });
            }
        }
    }
}
