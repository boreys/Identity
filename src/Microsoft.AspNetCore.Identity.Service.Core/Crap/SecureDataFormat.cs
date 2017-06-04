using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity.Service.Core
{
    public class SecureDataFormat<TData> : ISecureDataFormat<TData>
    {
        private readonly IDataSerializer<TData> _serializer;
        private readonly IDataProtector _protector;

        public SecureDataFormat(IDataSerializer<TData> serializer, IDataProtector protector)
        {
            _serializer = serializer;
            _protector = protector;
        }

        public string Protect(TData data)
        {
            return Protect(data, purpose: null);
        }

        public string Protect(TData data, string purpose)
        {
            var userData = _serializer.Serialize(data);

            var protector = _protector;
            if (!string.IsNullOrEmpty(purpose))
            {
                protector = protector.CreateProtector(purpose);
            }

            var protectedData = protector.Protect(userData);
            return Base64UrlEncoder.Encode(protectedData);
        }

        public TData Unprotect(string protectedText)
        {
            return Unprotect(protectedText, purpose: null);
        }

        public TData Unprotect(string protectedText, string purpose)
        {
            try
            {
                if (protectedText == null)
                {
                    return default(TData);
                }

                var protectedData = Base64UrlEncoder.DecodeBytes(protectedText);
                if (protectedData == null)
                {
                    return default(TData);
                }

                var protector = _protector;
                if (!string.IsNullOrEmpty(purpose))
                {
                    protector = protector.CreateProtector(purpose);
                }

                var userData = protector.Unprotect(protectedData);
                if (userData == null)
                {
                    return default(TData);
                }

                return _serializer.Deserialize(userData);
            }
            catch
            {
                // TODO trace exception, but do not leak other information
                return default(TData);
            }
        }
    }
}
