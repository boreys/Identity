// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Applications.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity.Service.Claims;
using Microsoft.AspNetCore.Identity.Service.Core;
using Microsoft.AspNetCore.Identity.Service.Core.Claims;
using Microsoft.AspNetCore.Identity.Service.Metadata;
using Microsoft.AspNetCore.Identity.Service.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Options.Infrastructure;

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

            services.TryAddEnumerable(ServiceDescriptor.Transient<ConfigureDefaultOptions<ApplicationTokenOptions>, IdentityTokensOptionsConfigurationDefaultSetup>());
            services.TryAddEnumerable(ServiceDescriptor.Transient<IConfigureOptions<ApplicationTokenOptions>, IdentityTokensOptionsDefaultSetup>());

            // Protocol services
            services.TryAddTransient<ITokenManager, TokenManager>();
            services.TryAddTransient<IAuthorizationCodeIssuer, AuthorizationCodeIssuer>();
            services.TryAddTransient<IAccessTokenIssuer, JwtAccessTokenIssuer>();
            services.TryAddTransient<IIdTokenIssuer, JwtIdTokenIssuer>();
            services.TryAddTransient<IRefreshTokenIssuer, RefreshTokenIssuer>();
            services.TryAddTransient<IKeySetMetadataProvider, DefaultKeySetMetadataProvider>();

            // Infrastructure services
            services.TryAddSingleton<ITimeStampManager, TimeStampManager>();
            services.TryAddTransient<ITokenHasher, TokenHasher>();
            services.TryAddTransient<ISecureDataFormat<AuthorizationCode>, SecureDataFormat<AuthorizationCode>>();
            services.TryAddTransient<ISecureDataFormat<RefreshToken>, SecureDataFormat<RefreshToken>>();
            services.TryAddSingleton(sp => sp.GetDataProtectionProvider().CreateProtector("IdentityProvider"));
            services.TryAddTransient<JwtSecurityTokenHandler, JwtSecurityTokenHandler>();
            services.TryAddTransient<IDataSerializer<AuthorizationCode>, TokenDataSerializer<AuthorizationCode>>();
            services.TryAddTransient<IDataSerializer<RefreshToken>, TokenDataSerializer<RefreshToken>>();

            // Validation
            services.TryAddTransient<IAuthorizationRequestFactory, AuthorizationRequestFactory>();
            services.TryAddTransient<ITokenRequestFactory, TokenRequestFactory>();
            services.TryAddTransient<ILogoutRequestFactory, LogoutRequestFactory>();

            // Metadata
            services.TryAddSingleton<IConfigurationManager, DefaultConfigurationManager>();
            services.TryAddSingleton<IConfigurationMetadataProvider, DefaultConfigurationMetadataProvider>();
            services.TryAddSingleton<ITimeStampManager, TimeStampManager>();

            // Other stuff
            services.TryAddSingleton<IAuthorizationResponseFactory, DefaultAuthorizationResponseFactory>();
            services.TryAddSingleton<IAuthorizationResponseParameterProvider, DefaultAuthorizationResponseParameterProvider>();
            services.TryAddSingleton<ITokenResponseFactory, DefaultTokenResponseFactory>();
            services.TryAddSingleton<ITokenResponseParameterProvider, DefaultTokenResponseParameterProvider>();
            services.TryAddSingleton<ITokenClaimsManager, DefaultTokenClaimsManager>();
            services.TryAddSingleton(new ProtocolErrorProvider());
            services.TryAddSingleton<ISigningCredentialsPolicyProvider, DefaultSigningCredentialsPolicyProvider>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ISigningCredentialsSource, DefaultSigningCredentialsSource>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ISigningCredentialsSource, DeveloperCertificateSigningCredentialsSource>());

            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, DefaultTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, GrantedTokensTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, NonceTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, ScopesTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, TimestampsTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, TokenHashTokenClaimsProvider>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITokenClaimsProvider, ProofOfKeyForCodeExchangeTokenClaimsProvider>());
            services.TryAddTransient<LoginManager>();

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
    }
}
