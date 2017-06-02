// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Microsoft.AspNetCore.Identity.Service
{
    public class ProtocolErrorProvider
    {
        public virtual OpenIdConnectMessage InvalidRedirectUri(string redirectUri)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The redirect uri '{redirectUri}' is not registered.");
        }

        public virtual OpenIdConnectMessage InvalidLogoutRedirectUri(string logoutUri)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The logout redirect uri '{logoutUri}' is not registered.");
        }

        public virtual OpenIdConnectMessage InvalidGrantType(string grantType)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The grant type '{grantType}' is not a valid grant type.");
        }

        public virtual OpenIdConnectMessage InvalidClientId(string clientId)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The client id '{clientId}' is not associated with any application.");
        }

        public virtual OpenIdConnectMessage InvalidAuthorizationCode()
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The authorization code presented is not valid or has expired.");
        }

        public virtual OpenIdConnectMessage TooManyParameters(string parameterName)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The parameter '{parameterName}' must be unique.");
        }

        public virtual OpenIdConnectMessage MissingPolicy()
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The 'p' parameter is missing.");
        }

        public virtual OpenIdConnectMessage MissingRequiredParameter(string parameterName)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The request is missing the required parameter {parameterName}.");
        }

        public virtual OpenIdConnectMessage InvalidParameterValue(string value, string parameterName)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"{value} is not a valid value for the parameter {parameterName}.");
        }

        public virtual OpenIdConnectMessage RequiresLogin()
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The request requires the user to explicitly login.");
        }

        public virtual OpenIdConnectMessage MissingOpenIdScope()
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The request is missing the required value 'openid' on the 'scope' parameter.");
        }

        public virtual OpenIdConnectMessage ResponseTypeNoneNotAllowed()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The parameter {OpenIdConnectParameterNames.ResponseType} must not contain any other value when the value 'none' is used.");
        }

        public virtual OpenIdConnectMessage InvalidLifetime()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The token is not yet active or it has expired.");
        }

        public virtual OpenIdConnectMessage InvalidCodeVerifier()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The code_verifier is missing or invalid.");
        }

        public virtual OpenIdConnectMessage MultipleResourcesNotSupported(string resourceName, string name)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"Can't get an access token for multiple resources '{resourceName}','{name}'.");
        }

        public virtual OpenIdConnectMessage InvalidGrant()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                "The given grant is not valid.");
        }

        public virtual OpenIdConnectMessage InvalidResponseTypeModeCombination(string responseType, string responseMode)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The value '{responseMode}' for the '{OpenIdConnectParameterNames.ResponseMode}' " +
                $"parameter is not compatible with the value '{responseMode}' for the '{OpenIdConnectParameterNames.ResponseType}' parameter.");
        }

        public virtual OpenIdConnectMessage InvalidClientCredentials()
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, "Invalid client credentials.");
        }

        public virtual OpenIdConnectMessage MismatchedRedirectUrl(string redirectUri)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The uri '{redirectUri}' must match the uri used during authorization.");
        }

        public virtual OpenIdConnectMessage InvalidScope(string scope)
        {
            return CreateError(IdentityErrorCodes.InvalidRequest, $"The scope '{scope}' is not valid.");
        }

        public virtual OpenIdConnectMessage UnauthorizedScope()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                "One or more scopes on the request are not allowed by the given grant.");
        }

        public virtual OpenIdConnectMessage InvalidUriFormat(string redirectUri)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"'{redirectUri}' must be an absolute uri without a fragment");
        }

        public virtual OpenIdConnectMessage InvalidPromptValue(string promptValue)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The prompt value '{promptValue}' is not valid.");
        }

        public virtual OpenIdConnectMessage PromptNoneMustBeTheOnlyValue(string promptValue)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The prompt value 'none' can't be used in conjunction with other prompt values '{promptValue}'");
        }

        public virtual OpenIdConnectMessage InvalidCodeChallengeMethod(string challengeMethod)
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The code challenge method '{challengeMethod ?? "plain"}' is invalid. Only S256 is supported.");
        }

        public virtual OpenIdConnectMessage InvalidCodeChallenge()
        {
            return CreateError(
                IdentityErrorCodes.InvalidRequest,
                $"The provided code challenge must be 43 characters long.");
        }

        private OpenIdConnectMessage CreateError(string code, string description, string uri = null) =>
            new OpenIdConnectMessage
            {
                Error = code,
                ErrorDescription = description,
                ErrorUri = uri
            };
    }
}
