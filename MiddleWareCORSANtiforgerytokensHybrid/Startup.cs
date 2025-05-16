using Microsoft.Owin;
using Owin;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Linq;
using System.Net;

[assembly: OwinStartup(typeof(MiddleWareCORSANtiforgerytokensHybrid.WcfService))]
public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        var config = new HttpConfiguration();

        // Enable CORS (Allow all origins for demo)
        var cors = new EnableCorsAttribute("*", "*", "*");
        config.EnableCors(cors);

        // Configure Anti-Forgery Token (Example using JWT)
        config.MessageHandlers.Add(new AntiForgeryTokenHandler());

        // Map WCF routes
        config.Routes.MapHttpRoute(
            name: "WcfService",
            routeTemplate: "api/{controller}/{action}",
            defaults: new { controller = "WcfService" }
        );

        app.UseWebApi(config);
    }
}

// Custom Anti-Forgery Token Handler
public class AntiForgeryTokenHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Skip token validation for GET requests
        if (request.Method == HttpMethod.Get)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        // Check if header exists
        if (!request.Headers.TryGetValues("X-CSRF-Token", out var tokenValues))
        {
            return new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                ReasonPhrase = "Anti-Forgery Token Missing"
            };
        }

        // Get first token safely (if multiple values exist)
        string token = tokenValues.FirstOrDefault();

        if (string.IsNullOrEmpty(token))
        {
            return new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                ReasonPhrase = "Empty Anti-Forgery Token"
            };
        }

        // Validate token (compare against stored value or cryptographic validation)
        if (token != "VALID_SECRET_TOKEN") // Replace with your validation logic
        {
            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                ReasonPhrase = "Invalid Anti-Forgery Token"
            };
        }

        return await base.SendAsync(request, cancellationToken);
    }
}