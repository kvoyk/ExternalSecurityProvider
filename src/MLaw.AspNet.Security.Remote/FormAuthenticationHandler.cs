using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;

namespace MLaw.AspNet.Security.Remote
{
    public class FormAuthenticationHandler : RemoteAuthenticationHandler<FormAuthenticationOptions>
    {
        private readonly IOptionsMonitor<FormAuthenticationOptions> _options;
        private readonly ILoggerFactory _logger;
        private readonly UrlEncoder _encoder;
        protected HttpClient Backchannel => Options.Backchannel;
        public FormAuthenticationHandler(
            IOptionsMonitor<FormAuthenticationOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _options = options;
            _logger = logger;
            _encoder = encoder;
        }

        protected  override  Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            string authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
            Context.Response.Redirect(authorizationEndpoint);
            return Task.CompletedTask;
        }


        protected  string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {

            string state = Options.StateDataFormat.Protect(properties);
            Dictionary<string, string> parameters = new Dictionary<string, string>
            {
                { "redirectUrl", redirectUri },
                { "state", state }
            };
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);

        }


        protected override  Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {

            ClaimsIdentity identity = new ClaimsIdentity(ClaimsIssuer);
            IQueryCollection query = Request.Query;

            StringValues state = query["state"];
            AuthenticationProperties properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return  Task.FromResult(HandleRequestResult.Fail("The  state was missing or invalid."));
            }

            if (!ValidateCorrelationId(properties))
            {
                return Task.FromResult(HandleRequestResult.Fail("Correlation failed."));
            }
            StringValues codeValues = query["code"];
            string code = codeValues.FirstOrDefault();
            FormAuthenticationResponse response =  ValidateAndGetDataAsync(code, Options.UserInformationEndpoint).Result;
            if (response.Error != null)
            {
                return Task.FromResult(HandleRequestResult.Fail(response.Error.Message));
            }


            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier, response.NameIdentifier, ClaimValueTypes.String, ClaimsIssuer),
                new Claim(ClaimTypes.Name, response.Name, ClaimValueTypes.String, ClaimsIssuer),
                new Claim(ClaimTypes.Email, response.Email, ClaimValueTypes.String, ClaimsIssuer),

            };
            identity.AddClaims(claims);
            AuthenticationTicket ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Options.ClaimsIssuer);
            return Task.FromResult(HandleRequestResult.Success(ticket));

        }

        protected  async Task<FormAuthenticationResponse> ValidateAndGetDataAsync(string code, string redirectUri)
        {
            Dictionary<string, string> tokenRequestParameters = new Dictionary<string, string>()
            {
                { "clientId", Options.ClientId },
                { "clientSecret", Options.ClientSecret },
                { "code", code }
            };

            FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.UserInformationEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            HttpResponseMessage response = await Backchannel.SendAsync( requestMessage, Context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                JObject payload = JObject.Parse(await response.Content.ReadAsStringAsync());
                return FormAuthenticationResponse.Success(payload);
            }

                string error = "OAuth token endpoint failure: " + await Display(response);
                return FormAuthenticationResponse.Failed(new Exception(error));
            
        }
        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

    }
}
