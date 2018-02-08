using System;
using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace MLaw.AspNet.Security.Remote
{
    public class FormAuthenticationOptions : RemoteAuthenticationOptions
    {
        public FormAuthenticationOptions()
        {
            CallbackPath = new PathString(FormAuthenticationDefaults.CallbackPath);
            ClaimsIssuer = FormAuthenticationDefaults.Issuer;
        }
        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrEmpty(ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientId)), nameof(ClientId));
            }
            if (string.IsNullOrEmpty(ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientSecret)), nameof(ClientSecret));
            }
            if (string.IsNullOrEmpty(AuthorizationEndpoint))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(AuthorizationEndpoint)), nameof(AuthorizationEndpoint));
            }

            if (string.IsNullOrEmpty(UserInformationEndpoint))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(UserInformationEndpoint)), nameof(UserInformationEndpoint));
            }

            if (!CallbackPath.HasValue)
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(CallbackPath)), nameof(CallbackPath));
            }
        }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public  string AuthenticationType { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string UserInformationEndpoint { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

    }
}
