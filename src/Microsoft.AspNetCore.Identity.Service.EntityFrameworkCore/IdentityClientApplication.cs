// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Identity.Service
{
    public class IdentityClientApplication : IdentityClientApplication<string>
    {
    }

    public class IdentityClientApplication<TUserKey> :
        IdentityClientApplication<string, TUserKey>
        where TUserKey : IEquatable<TUserKey>
    {
    }

    public class IdentityClientApplication<TApplicationKey, TUserKey> :
        IdentityClientApplication<
            TApplicationKey,
            TUserKey,
            IdentityClientApplicationScope<TApplicationKey>,
            IdentityClientApplicationClaim<TApplicationKey>,
            IdentityClientApplicationRedirectUri<TApplicationKey>>
        where TApplicationKey : IEquatable<TApplicationKey>
        where TUserKey : IEquatable<TUserKey>
    {
    }

    public class IdentityClientApplication<TKey, TUserKey, TScope, TApplicationClaim, TRedirectUri>
        where TKey : IEquatable<TKey>
        where TUserKey : IEquatable<TUserKey>
        where TScope : IdentityClientApplicationScope<TKey>
        where TApplicationClaim : IdentityClientApplicationClaim<TKey>
        where TRedirectUri : IdentityClientApplicationRedirectUri<TKey>
    {
        public TKey Id { get; set; }
        public string Name { get; set; }
        public TUserKey UserId { get; set; }
        public string ClientId { get; set; }
        public string ClientSecretHash { get; set; }
        public string ConcurrencyStamp { get; set; }
        public ICollection<TScope> Scopes { get; set; }
        public ICollection<TApplicationClaim> Claims { get; set; }
        public ICollection<TRedirectUri> RedirectUris { get; set; }
    }
}
