using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.Service;

namespace Microsoft.AspNetCore.Applications.Authentication
{
    public interface ILoginContextProvider
    {
        Task<LoginContext> GetLoginContextAsync();
        Task LogInAsync(ClaimsPrincipal user, ClaimsPrincipal application);
        Task LogOutAsync(ClaimsPrincipal user, ClaimsPrincipal application);
    }
}
