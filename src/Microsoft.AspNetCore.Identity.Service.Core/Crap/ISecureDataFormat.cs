using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.AspNetCore.Identity.Service.Core
{
    public interface ISecureDataFormat<TData>
    {
        string Protect(TData data);
        string Protect(TData data, string purpose);
        TData Unprotect(string protectedText);
        TData Unprotect(string protectedText, string purpose);
    }
}
