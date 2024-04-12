using System.Net.Http.Headers;

namespace RealCreate.Web2.Services
{
    public class HttpClientInterceptorService: DelegatingHandler
    {
        private readonly ICookieService _cookieService;

        public HttpClientInterceptorService(ICookieService cookieService)
        {
            _cookieService = cookieService;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var jwt = _cookieService.Get(Constants.AuthCookieToken);
            if (!string.IsNullOrWhiteSpace(jwt))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            }

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
