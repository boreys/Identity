// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity.Service
{
    public class IdentityClientApplicationsAuthorizationOptionsSetup : IConfigureOptions<AuthorizationOptions>
    {
        private readonly IOptions<TokenOptions> tokenOptions;

        public IdentityClientApplicationsAuthorizationOptionsSetup(IOptions<TokenOptions> tokenOptions)
        {
            this.tokenOptions = tokenOptions;
        }

        public void Configure(AuthorizationOptions options)
        {
            options.AddPolicy(TokenOptions.LoginPolicyName, tokenOptions.Value.LoginPolicy);
            options.AddPolicy(TokenOptions.SessionPolicyName, tokenOptions.Value.SessionPolicy);
            options.AddPolicy(TokenOptions.ManagementPolicyName, tokenOptions.Value.ManagementPolicy);
        }
    }
}
