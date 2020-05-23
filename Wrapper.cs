using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net;
using System.Web;
using System.Text;

namespace FAExportOAuthWrapper {
    /// <summary>
    /// A set of Azure Functions endpoints that let OAuth2 clients obtain FurAffinity credentials from a user for use with FAExport.
    /// </summary>
    public static class Wrapper {
        /// <summary>
        /// Gets the client secret for the given client ID from the Azure Functions configuration or local.settings.json file.
        /// </summary>
        /// <param name="clientId">The client ID</param>
        /// <returns>The client secret, or null if not found</returns>
        private static string GetClientSecret(string clientId) {
            if (clientId == null)
                return null;
            else if (!int.TryParse(clientId, out int i))
                return null;
            else
                return Environment.GetEnvironmentVariable($"ClientSecret_{i}", EnvironmentVariableTarget.Process);
        }

        /// <summary>
        /// Encrypts a string using the client secret.
        /// </summary>
        /// <param name="clientSecret">The client secret</param>
        /// <param name="val">The string to encrypt</param>
        /// <returns>A base-16 encoded encrypted string</returns>
        private static string Encrypt(string clientSecret, string val) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string enc = AESGCM.SimpleEncrypt(val, key);
            return Uri.EscapeDataString(enc);
        }

        /// <summary>
        /// Decrypts a string using the client secret.
        /// </summary>
        /// <param name="clientSecret">The client secret</param>
        /// <param name="enc">A base-16 encoded encrypted string</param>
        /// <returns>The original string</returns>
        private static string Decrypt(string clientSecret, string enc) {
            byte[] key = Convert.FromBase64String(clientSecret);

            string dec = AESGCM.SimpleDecrypt(enc, key);
            return dec;
        }

        /// <summary>
        /// OAuth2 authorization endpoint.
        /// 
        /// Required parameters:
        /// * response_type (must be "code")
        /// * client_id (must correspond to a client secret in the Azure Functions configuration or local.settings.json)
        /// * redirect_uri
        /// 
        /// Optional parameters:
        /// * state
        /// 
        /// Ignored parameters:
        /// * scope
        /// </summary>
        [FunctionName("auth")]
        public static IActionResult Auth([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req) {
            string response_type = req.Query["response_type"];
            if (response_type != "code")
                return new BadRequestObjectResult(new { error = "The response_type is invalid or missing." });

            string client_id = req.Query["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestObjectResult(new { error = "The client_id is invalid or missing." });

            string redirect_uri = req.Query["redirect_uri"];
            if (Uri.TryCreate(redirect_uri, UriKind.Absolute, out Uri redirect_uri_parsed) == false)
                return new BadRequestObjectResult(new { error = "The redirect_uri is invalid or missing." });

            StringBuilder hidden_inputs = new StringBuilder();
            hidden_inputs.AppendLine($"<input type='hidden' name='client_id' value='{HttpUtility.HtmlAttributeEncode(client_id)}' />");
            hidden_inputs.AppendLine($"<input type='hidden' name='redirect_uri' value='{HttpUtility.HtmlAttributeEncode(redirect_uri)}' />");

            string state = req.Query["state"];
            if (state != null)
                hidden_inputs.AppendLine($"<input type='hidden' name='state' value='{HttpUtility.HtmlAttributeEncode(state)}' />");

            string html = string.Format(@"<!DOCTYPE html>
<html>
    <head>
        <title>FurAffinity API Key OAuth2 Wrapper</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
    </head>
<body class='m-2'>
    <p>
        Enter the values of your FurAffinity ""a"" and ""b"" session cookies.<br />
        See the <a href='https://faexport.spangle.org.uk/docs' target='_blank'>FAExport</a> documentation for more info about how to obtain these.
    </p>
    <form action='postback' method='post'>
        {0}
        <div class='form-group mr-2'>
            <label for='a'>a</label>
            <input type='text' name='a' id='a' class='form-control' />
        </div>
        <div class='form-group mr-2'>
            <label for='b'>b</label>
            <input type='text' name='b' id='b' class='form-control' />
        </div>
        <input type='submit' value='Submit' class='btn btn-primary' />
    </form>
    <hr />
    <p class='font-weight-bold'>This page is not part of FurAffinity or FAExport. By entering your API key, you are giving {1} and {2} access to your account.</p>
    <hr />
    <p class='small'>
        <a href='https://github.com/IsaacSchemm/faexport-oauth2-wrapper' target='_blank'>
            View source on GitHub
        </a>
    </p>
</body>
</html>", hidden_inputs.ToString(), WebUtility.HtmlEncode(req.Host.Host), redirect_uri_parsed.Host);
            return new FileContentResult(Encoding.UTF8.GetBytes(html), "text/html; charset=utf-8");
        }

        /// <summary>
        /// Process an API key entry by the user and redirect to the redirect_uri.
        /// 
        /// Two URL parameters will be added:
        /// * code - an encrypted version of the API key (encrypted using the client secret)
        /// * state - a copy of the state parameter sent with the /auth request, if any
        /// </summary>
        [FunctionName("postback")]
        public static async Task<IActionResult> Postback([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            string client_secret = GetClientSecret(client_id);
            if (client_secret == null)
                return new BadRequestResult();

            string redirect_uri = req.Form["redirect_uri"];
            if (redirect_uri == null)
                return new BadRequestResult();

            var uriBuilder = new UriBuilder(redirect_uri);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            string a = req.Form["a"];
            if (a == null)
                return new BadRequestResult();

            string b = req.Form["b"];
            if (b == null)
                return new BadRequestResult();

            try {
                try {
                    var hreq = WebRequest.CreateHttp("https://faexport.spangle.org.uk/notifications/submissions.json");
                    hreq.UserAgent = "faexport-oauth2-wrapper/0.0 (https://github.com/IsaacSchemm/faexport-oauth2-wrapper)";
                    hreq.Headers["FA_COOKIE"] = $"b={b}; a={a}";

                    using (var resp = await hreq.GetResponseAsync())
                    using (var sr = new StreamReader(resp.GetResponseStream())) { }
                } catch (WebException ex) when (ex.Response is HttpWebResponse resp) {
                    using (var sr = new StreamReader(resp.GetResponseStream())) {
                        string json = await sr.ReadToEndAsync();
                        var response_obj = JsonConvert.DeserializeAnonymousType(json, new {
                            error = ""
                        });

                        return new ContentResult {
                            Content = string.Format(@"FAExport returned an error:
{0}

Press the Back button to try again.
", response_obj.error),
                            ContentType = "text/plain",
                            StatusCode = (int)resp.StatusCode
                        };
                    }
                }
            } catch (Exception) {
                return new ContentResult {
                    Content = "Could not connect to FAExport.",
                    ContentType = "text/plain",
                    StatusCode = (int)HttpStatusCode.BadGateway
                };
            }

            query["code"] = Encrypt(client_secret, $"b={b}; a={a}");

            string state = req.Form["state"];
            if (state != null)
                query["state"] = state;

            uriBuilder.Query = query.ToString();
            return new RedirectResult(uriBuilder.ToString());
        }

        /// <summary>
        /// OAuth2 token request endpoint.
        /// 
        /// Required parameters:
        /// * grant_type (must be authorization_code)
        /// * code (the encrypted API key from the prior step)
        /// * client_id
        /// * client_secret
        /// 
        /// Ignored parameters:
        /// * redirect_uri
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [FunctionName("token")]
        public static async Task<IActionResult> Token([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req) {
            string client_id = req.Form["client_id"];
            if (client_id == null)
                return new OkObjectResult(new {
                    error = "unauthorized_client",
                    error_description = "client_id is missing"
                });

            string client_secret = req.Form["client_secret"];
            if (client_secret == null || client_secret != GetClientSecret(client_id))
                return new OkObjectResult(new {
                    error = "unauthorized_client",
                    error_description = "client_secret is missing or does not match"
                });

            string grant_type = req.Form["grant_type"];
            if (grant_type != "authorization_code")
                return new OkObjectResult(new {
                    error = "unsupported_grant_type",
                    error_description = "Only authorization_code is supported"
                });

            string code = req.Form["code"];
            if (string.IsNullOrEmpty(code))
                return new OkObjectResult(new {
                    error = "invalid_request",
                    error_description = "code is missing or invalid"
                });

            string faCookie = Decrypt(client_secret, code);

            return new OkObjectResult(new {
                access_token = faCookie,
                token_type = "facookie"
            });
        }
    }
}
