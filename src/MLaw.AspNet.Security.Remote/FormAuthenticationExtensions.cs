using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace MLaw.AspNet.Security.Remote
{
    public static class FormAuthenticationExtensions
    {
        public static AuthenticationBuilder AddRemote(this AuthenticationBuilder builder)
        {
            return builder.AddRemote(FormAuthenticationDefaults.AuthenticationScheme, options => { });     
        }
        public static AuthenticationBuilder AddCosign2(this AuthenticationBuilder builder, Action<FormAuthenticationOptions> configureOptions)
        {
            return builder.AddRemote(FormAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }
        public static AuthenticationBuilder AddRemote(this AuthenticationBuilder builder, string authenticationScheme, Action<FormAuthenticationOptions> configureOptions)
        {
            return builder.AddRemote(authenticationScheme, FormAuthenticationDefaults.DisplayName, configureOptions);
        }
        public static AuthenticationBuilder AddRemote(this AuthenticationBuilder builder, 
            string authenticationScheme, 
            string displayName, 
            Action<FormAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<FormAuthenticationOptions>, FormPostConfigureOptions<FormAuthenticationOptions, FormAuthenticationHandler>>());
            return builder.AddRemoteScheme<FormAuthenticationOptions, FormAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
