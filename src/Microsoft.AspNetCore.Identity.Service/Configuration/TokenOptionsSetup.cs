// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity.Service.Configuration
{
    public class TokenOptionsSetup : IConfigureOptions<TokenOptions>
    {
        private readonly IOptions<IdentityOptions> _options;

        public TokenOptionsSetup(IOptions<IdentityOptions> options)
        {
            _options = options;
        }

        public void Configure(TokenOptions options)
        {
            options.IdTokenOptions.UserClaims
                .AddSingle(TokenClaimTypes.Subject, _options.Value.ClaimsIdentity.UserIdClaimType);

            options.IdTokenOptions.UserClaims
                .AddSingle(TokenClaimTypes.Name, _options.Value.ClaimsIdentity.UserNameClaimType);

            options.AccessTokenOptions.UserClaims
                .AddSingle(TokenClaimTypes.Name, _options.Value.ClaimsIdentity.UserNameClaimType);

            options.LoginPolicy = new AuthorizationPolicyBuilder(options.LoginPolicy)
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
                .Build();

            options.ManagementPolicy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
                .AddAuthenticationSchemes(TokenOptions.CookieAuthenticationScheme)
                .AddRequirements(new ApplicationManagementRequirement())
                .Build();
        }
    }
}
