using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace MLaw.AspNet.Security.Remote
{
    public class FormPostConfigureOptions<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : FormAuthenticationOptions, new()
        where THandler : FormAuthenticationHandler
    {
        private readonly IDataProtectionProvider _dp;
        public FormPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }
        public void PostConfigure(string name, TOptions options)
        {

            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Form Idp Authentication handler");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
            //create backchannel

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(THandler).FullName, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }
    }
}
