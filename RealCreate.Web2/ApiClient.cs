using System.Net.Http;

namespace RealCreate.Web2
{
    public class ApiClient
    {
        public async Task<LoginResult?> LoginAsync(string email, string password)
        {
            HttpClient httpClient = new HttpClient();
            var response = await httpClient.PostAsJsonAsync("http://localhost:5430/api/account/login", new { email, password });

            if (response.IsSuccessStatusCode)
                return await response.Content.ReadFromJsonAsync<LoginResult>();

            return null;
        }
    }
}
