using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity.Service.Session
{
    public interface ILoginContextProvider
    {
        Task<LoginContext> GetLoginContextAsync();
        Task LogInAsync(ClaimsPrincipal user, ClaimsPrincipal application);
        Task LogOutAsync(ClaimsPrincipal user, ClaimsPrincipal application);
    }
}
