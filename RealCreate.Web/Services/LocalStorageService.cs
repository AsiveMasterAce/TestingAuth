using Microsoft.JSInterop;
using System;
using System.Threading.Tasks;

namespace RealCreate.Web.Services
{
    public class LocalStorageService
    {
        private readonly IJSRuntime _jsRuntime;

        public LocalStorageService(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        public async Task SetItemAsync(string key, string value)
        {
            try
            {
                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", key, value);
            }
            catch (Exception ex)
            {
                // Handle or log the exception as needed
                Console.WriteLine($"Error setting item in local storage: {ex.Message}");
            }
        }

        public async Task<string> GetItemAsync(string key)
        {
            try
            {
                return await _jsRuntime.InvokeAsync<string>("localStorage.getItem", key);
            }
            catch (Exception ex)
            {
                // Handle or log the exception as needed
                Console.WriteLine($"Error getting item from local storage: {ex.Message}");
                return null; // Return null or a default value when an exception occurs
            }
        }

        public async Task RemoveItemAsync(string key)
        {
            try
            {
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", key);
            }
            catch (Exception ex)
            {
                // Handle or log the exception as needed
                Console.WriteLine($"Error removing item from local storage: {ex.Message}");
            }
        }
    }
}
