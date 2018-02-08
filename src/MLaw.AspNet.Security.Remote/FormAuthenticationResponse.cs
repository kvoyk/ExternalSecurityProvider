using System;
using Newtonsoft.Json.Linq;

namespace MLaw.AspNet.Security.Remote
{
    public class FormAuthenticationResponse
    {
        private FormAuthenticationResponse(JObject response)
        {
            Response = response;
            Name = response.Value<string>("name");
            NameIdentifier = response.Value<string>("nameidentifier");
            Email = response.Value<string>("email");
        }

        private FormAuthenticationResponse(Exception error)
        {
            Error = error;
        }

        public static FormAuthenticationResponse Success(JObject response)
        {
            return new FormAuthenticationResponse(response);
        }

        public static FormAuthenticationResponse Failed(Exception error)
        {
            return new FormAuthenticationResponse(error);
        }

        public JObject Response { get; set; }
        public string Name { get; set; }
        public string NameIdentifier { get; set; }
        public string Email { get; set; }
        public Exception Error { get; set; }
    }
}
