using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity.Service.Session
{
    public interface ILoginFactory
    {
        Task<ClaimsPrincipal> GetUserAsync(string userId);
        Task<ClaimsPrincipal> GetApplicationAsync(string clientId);
    }
}
