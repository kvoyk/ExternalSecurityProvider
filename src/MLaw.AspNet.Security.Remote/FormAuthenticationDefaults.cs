namespace MLaw.AspNet.Security.Remote
{
    public static class FormAuthenticationDefaults
    {
        public static readonly string AuthenticationScheme = "Remote";
        public static readonly string DisplayName = "Remote";
        //public const string AuthenticationType = "Form";
        public const string Issuer = "Remote";
        public const string CallbackPath = "/signin-remote";

    }
}
