// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity.Service.Claims;
using Microsoft.AspNetCore.Identity.Service.Core;
using Microsoft.AspNetCore.Identity.Service.Core.Claims;
using Microsoft.AspNetCore.Identity.Service.Metadata;
using Microsoft.AspNetCore.Identity.Service.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.AspNetCore.Identity.Service
{
    public static class ApplicationTokensServiceCollectionExtensions
    {
        public static IServiceCollection AddApplicationTokens(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddOptions();
            services.TryAdd(CreateServices());

            return services;
        }

        public static IServiceCollection AddApplicationTokens(
            this IServiceCollection services,
            Action<ApplicationTokenOptions> configure)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure));
            }

            services.AddApplicationTokens();
            services.Configure(configure);

            return services;
        }

        private static IEnumerable<ServiceDescriptor> CreateServices()
        {
            // Protocol services
            yield return ServiceDescriptor.Transient<ITokenManager, TokenManager>();
            yield return ServiceDescriptor.Transient<IAuthorizationCodeIssuer, AuthorizationCodeIssuer>();
            yield return ServiceDescriptor.Transient<IAccessTokenIssuer, JwtAccessTokenIssuer>();
            yield return ServiceDescriptor.Transient<IIdTokenIssuer, JwtIdTokenIssuer>();
            yield return ServiceDescriptor.Transient<IRefreshTokenIssuer, RefreshTokenIssuer>();
            yield return ServiceDescriptor.Transient<IKeySetMetadataProvider, DefaultKeySetMetadataProvider>();

            // Infrastructure services
            yield return ServiceDescriptor.Singleton<ITimeStampManager, TimeStampManager>();
            yield return ServiceDescriptor.Transient<ITokenHasher, TokenHasher>();
            yield return ServiceDescriptor.Transient<ISecureDataFormat<AuthorizationCode>, SecureDataFormat<AuthorizationCode>>();
            yield return ServiceDescriptor.Transient<ISecureDataFormat<RefreshToken>, SecureDataFormat<RefreshToken>>();
            yield return ServiceDescriptor.Singleton(sp => sp.GetDataProtectionProvider().CreateProtector("IdentityProvider"));
            yield return ServiceDescriptor.Transient<JwtSecurityTokenHandler, JwtSecurityTokenHandler>();
            yield return ServiceDescriptor.Transient<IDataSerializer<AuthorizationCode>, TokenDataSerializer<AuthorizationCode>>();
            yield return ServiceDescriptor.Transient<IDataSerializer<RefreshToken>, TokenDataSerializer<RefreshToken>>();

            // Validation
            yield return ServiceDescriptor.Transient<IAuthorizationRequestFactory, AuthorizationRequestFactory>();
            yield return ServiceDescriptor.Transient<ITokenRequestFactory, TokenRequestFactory>();
            yield return ServiceDescriptor.Transient<ILogoutRequestFactory, LogoutRequestFactory>();

            // Metadata
            yield return ServiceDescriptor.Singleton<IConfigurationManager, DefaultConfigurationManager>();
            yield return ServiceDescriptor.Singleton<IConfigurationMetadataProvider, DefaultConfigurationMetadataProvider>();

            // Other stuff
            yield return ServiceDescriptor.Singleton<IAuthorizationResponseFactory, DefaultAuthorizationResponseFactory>();
            yield return ServiceDescriptor.Singleton<IAuthorizationResponseParameterProvider, DefaultAuthorizationResponseParameterProvider>();
            yield return ServiceDescriptor.Singleton<ITokenResponseFactory, DefaultTokenResponseFactory>();
            yield return ServiceDescriptor.Singleton<ITokenResponseParameterProvider, DefaultTokenResponseParameterProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsManager, DefaultTokenClaimsManager>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, DefaultTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, GrantedTokensTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, NonceTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, ScopesTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, TimestampsTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, TokenHashTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton<ITokenClaimsProvider, ProofOfKeyForCodeExchangeTokenClaimsProvider>();
            yield return ServiceDescriptor.Singleton(new ProtocolErrorProvider());
            yield return ServiceDescriptor.Singleton<ISigningCredentialsSource, DeveloperCertificateSigningCredentialsSource>();
            yield return ServiceDescriptor.Scoped<ISigningCredentialsPolicyProvider, DefaultSigningCredentialsPolicyProvider>();
            yield return ServiceDescriptor.Scoped<ISigningCredentialsSource, DefaultSigningCredentialsSource>();
        }
    }
}
