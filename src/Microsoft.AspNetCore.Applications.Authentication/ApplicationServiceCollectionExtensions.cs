// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Service;
using Microsoft.AspNetCore.Identity.Service.Configuration;
using Microsoft.AspNetCore.Identity.Service.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Options.Infrastructure;

namespace Microsoft.AspNetCore.Applications.Authentication
{
    public static class ApplicationServiceCollectionExtensions
    {
        public static IdentityBuilder AddApplications<TApplication>(this IdentityBuilder builder)
            where TApplication : class
        {
            var services = builder.Services;

            services.AddOptions();
            services.AddApplicationTokens();
            services.AddWebEncoders();
            services.AddDataProtection();
            services.AddAuthentication();

            builder.AddApplicationsCore<TApplication>();

            services.TryAdd(CreateServices(builder.UserType, typeof(TApplication)));

            services.AddCookieAuthentication(ApplicationsAuthenticationDefaults.CookieAuthenticationScheme, options =>
            {
                options.CookieHttpOnly = true;
                options.CookieSecure = CookieSecurePolicy.Always;
                options.CookiePath = "/tfp/Identity/signinsignup";
                options.AccessDeniedPath = "/tfp/Identity/signinsignup/Account/AccessDenied";
                options.CookieName = ApplicationsAuthenticationDefaults.CookieAuthenticationName;
            });
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/tfp/Identity/signinsignup/Account/Login";
                options.AccessDeniedPath = "/tfp/Identity/signinsignup/Account/AccessDenied";
                options.CookiePath = "/tfp/Identity/signinsignup";
            });
            services.ConfigureExternalCookie(options => options.CookiePath = $"/tfp/Identity/signinsignup");
            services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorRememberMeScheme, options => options.CookiePath = $"/tfp/Identity");
            services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme, options => options.CookiePath = $"/tfp/Identity");

            return builder;
        }

        private static IEnumerable<ServiceDescriptor> CreateServices(Type userType, Type applicationType)
        {
            yield return ServiceDescriptor.Singleton<IConfigureOptions<AuthorizationOptions>, IdentityClientApplicationsAuthorizationOptionsSetup>();
            yield return ServiceDescriptor.Transient<ConfigureDefaultOptions<ApplicationTokenOptions>, IdentityTokensOptionsConfigurationDefaultSetup>();
            yield return ServiceDescriptor.Transient<IConfigureOptions<ApplicationTokenOptions>, IdentityTokensOptionsDefaultSetup>();
            yield return ServiceDescriptor.Transient<IConfigureOptions<ApplicationTokenOptions>, TokenOptionsSetup>();

            yield return ServiceDescriptor.Transient(typeof(SessionManager), typeof(SessionManager<,>).MakeGenericType(userType, applicationType));

            var sessionType = typeof(SessionManager<,>).MakeGenericType(userType, applicationType);
            yield return ServiceDescriptor.Transient(sessionType, sessionType);
            yield return ServiceDescriptor.Transient(typeof(IRedirectUriResolver), typeof(ClientApplicationValidator<>).MakeGenericType(applicationType));
            yield return ServiceDescriptor.Singleton<FormPostResponseGenerator, FormPostResponseGenerator>();
            yield return ServiceDescriptor.Singleton<FragmentResponseGenerator, FragmentResponseGenerator>();
            yield return ServiceDescriptor.Singleton<QueryResponseGenerator, QueryResponseGenerator>();

            yield return ServiceDescriptor.Transient(typeof(IClientIdValidator), typeof(ClientApplicationValidator<>).MakeGenericType(applicationType));
            yield return ServiceDescriptor.Transient(typeof(IScopeResolver), typeof(ClientApplicationValidator<>).MakeGenericType(applicationType));
            yield return ServiceDescriptor.Singleton<IHttpContextAccessor, HttpContextAccessor>();
        }

        public static IdentityBuilder AddApplications<TApplication>(
            this IdentityBuilder builder,
            Action<ApplicationOptions> configure) where TApplication : class
        {
            builder.AddApplications<TApplication>();
            builder.Services.Configure(configure);
            return builder;
        }

        public static IdentityBuilder AddApplications(
            this IdentityBuilder builder,
            Action<ApplicationOptions> configure)
        {
            builder.Services.Configure(configure);
            return builder;
        }

        public static IdentityBuilder AddApplications(this IdentityBuilder builder)
        {
            return builder;
        }

    }
}
