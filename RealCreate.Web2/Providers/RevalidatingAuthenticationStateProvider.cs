﻿//using Microsoft.AspNetCore.Components.Authorization;
//using Microsoft.AspNetCore.Components.Server;
//using Microsoft.AspNetCore.Identity;
//using Microsoft.Extensions.Options;
//using System.Security.Claims;

//namespace RealCreate.Web2.Providers
//{
//    internal sealed class IdentityRevalidatingAuthenticationStateProvider(
//           ILoggerFactory loggerFactory,
//           IServiceScopeFactory scopeFactory,
//           IOptions<IdentityOptions> options)
//       : RevalidatingServerAuthenticationStateProvider(loggerFactory)
//    {
//        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

//        protected override async Task<bool> ValidateAuthenticationStateAsync(
//            AuthenticationState authenticationState, CancellationToken cancellationToken)
//        {
//            // Get the user manager from a new scope to ensure it fetches fresh data
//            await using var scope = scopeFactory.CreateAsyncScope();
//            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<>>();
//            return await ValidateSecurityStampAsync(userManager, authenticationState.User);
//        }

//        private async Task<bool> ValidateSecurityStampAsync(UserManager<> userManager, ClaimsPrincipal principal)
//        {
//            var user = await userManager.GetUserAsync(principal);
//            if (user is null)
//            {
//                return false;
//            }
//            else if (!userManager.SupportsUserSecurityStamp)
//            {
//                return true;
//            }
//            else
//            {
//                var principalStamp = principal.FindFirstValue(options.Value.ClaimsIdentity.SecurityStampClaimType);
//                var userStamp = await userManager.GetSecurityStampAsync(user);
//                return principalStamp == userStamp;
//            }
//        }
//    }
//}
