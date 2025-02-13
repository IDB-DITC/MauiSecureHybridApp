using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;

namespace MauiSecureApp
{
    public class LoginModel
    {
        [Required]
        [Display(Name = "Email Address")]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public string LoginFailureMessage { get; set; } = "Invalid Email or Password. Please try again.";

    }
    public class DecodedToken
    {
        private string keyId;
        private string issuer;
        private List<string> audience;
        private List<Claim> claims;
        private DateTime validTo;
        private string signatureAlgorithm;
        private string rawData;
        private string subject;
        private DateTime validFrom;
        private string encodedHeader;
        private string encodedPayload;

        public DecodedToken(string keyId, string issuer, List<string> audience, List<Claim> claims, DateTime validTo, string signatureAlgorithm, string rawData, string subject, DateTime validFrom, string encodedHeader, string encodedPayload)
        {
            this.keyId = keyId;
            this.issuer = issuer;
            this.audience = audience;
            this.claims = claims;
            this.validTo = validTo;
            this.signatureAlgorithm = signatureAlgorithm;
            this.rawData = rawData;
            this.subject = subject;
            this.validFrom = validFrom;
            this.encodedHeader = encodedHeader;
            this.encodedPayload = encodedPayload;
        }
    }
    public enum LoginStatus
    {
        None,
        Success,
        Failed
    }
    public interface ICustomAuthenticationStateProvider
    {
        public LoginStatus LoginStatus { get; set; }
        Task<AuthenticationState> GetAuthenticationStateAsync();
        Task LogInAsync(LoginModel loginModel);
        void Logout();
    }
    public class MauiAuthenticationStateProvider : AuthenticationStateProvider, ICustomAuthenticationStateProvider
    {
        //TODO: Place this in AppSettings or Client config file
        protected string LoginUri { get; set; } = "https://localhost:7157/login";

        public LoginStatus LoginStatus { get; set; } = LoginStatus.None;
        protected ClaimsPrincipal currentUser = new ClaimsPrincipal(new ClaimsIdentity());

        public MauiAuthenticationStateProvider()
        {
            //See: https://learn.microsoft.com/dotnet/maui/data-cloud/local-web-services
            //Android Emulator uses 10.0.2.2 to refer to localhost            
            LoginUri =
                DeviceInfo.Platform == DevicePlatform.Android ? LoginUri.Replace("localhost", "10.0.2.2") : LoginUri;
        }

        private HttpClient GetHttpClient()
        {
#if WINDOWS || MACCATALYST
            return new HttpClient();
#else
            return new HttpClient(new HttpsClientHandlerService().GetPlatformMessageHandler());
#endif
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {


            string? token = await SecureStorage.GetAsync("jwt");








            return await Task.FromResult(new AuthenticationState(currentUser));
        }

        public JwtSecurityToken ConvertJwtStringToJwtSecurityToken(string? jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);

            return token;
        }

        public DecodedToken DecodeJwt(JwtSecurityToken token)
        {
            var keyId = token.Header.Kid;
            var audience = token.Audiences.ToList();
            var claims = token.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();

            return new DecodedToken(
                keyId,
                token.Issuer,
                audience,
                claims,
                token.ValidTo,
                token.SignatureAlgorithm,
                token.RawData,
                token.Subject,
                token.ValidFrom,
                token.EncodedHeader,
                token.EncodedPayload
            );
        }



        public Task LogInAsync(LoginModel loginModel)
        {

            var loginTask = LogInAsyncCore(loginModel);
            NotifyAuthenticationStateChanged(loginTask);

            return loginTask;

            async Task<AuthenticationState> LogInAsyncCore(LoginModel loginModel)
            {



                var user = await LoginWithProviderAsync(loginModel);
                currentUser = user;

                return new AuthenticationState(currentUser);
            }
        }
        public void Logout()
        {
            LoginStatus = LoginStatus.None;
            currentUser = new ClaimsPrincipal(new ClaimsIdentity());
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(currentUser)));
        }

        private async Task<ClaimsPrincipal> LoginWithProviderAsync(LoginModel loginModel)
        {
            ClaimsPrincipal authenticatedUser;
            LoginStatus = LoginStatus.None;
            bool test = true;
            try
            {
                var httpClient = GetHttpClient();
                var loginData = new { loginModel.Email, loginModel.Password };
                if (test)
                {
                    var claims = new[] { new Claim(ClaimTypes.Name, loginModel.Email) };
                    var identity = new ClaimsIdentity(claims, "Custom authentication");
                    LoginStatus = LoginStatus.Success;
                    authenticatedUser = new ClaimsPrincipal(identity);
                }
                else
                {
                    var response = await httpClient.PostAsJsonAsync(LoginUri, loginData);

                    LoginStatus = response.IsSuccessStatusCode ? LoginStatus.Success : LoginStatus.Failed;

                    if (LoginStatus == LoginStatus.Success)
                    {
                        //var token = response.Content.ReadAsStringAsync().Result;
                        var claims = new[] { new Claim(ClaimTypes.Name, loginModel.Email) };
                        var identity = new ClaimsIdentity(claims, "Custom authentication");

                        authenticatedUser = new ClaimsPrincipal(identity);
                    }
                    else
                        authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity());
                }
                    
            }
            catch (Exception ex)
            {
                authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity());
            }

            return authenticatedUser;
        }
    }


    public class HttpsClientHandlerService
    {
        public HttpMessageHandler GetPlatformMessageHandler()
        {
#if ANDROID
            var handler = new Xamarin.Android.Net.AndroidMessageHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (cert != null && cert.Issuer.Equals("CN=localhost"))
                    return true;
                return errors == System.Net.Security.SslPolicyErrors.None;
            };
            return handler;
#elif IOS
        var handler = new NSUrlSessionHandler
        {
            TrustOverrideForUrl = IsHttpsLocalhost
        };
        return handler;
#else
            throw new PlatformNotSupportedException("Only Android and iOS supported.");
#endif
        }

#if IOS
    public bool IsHttpsLocalhost(NSUrlSessionHandler sender, string url, Security.SecTrust trust)
    {
        return url.StartsWith("https://localhost");
    }
#endif
    }
}
