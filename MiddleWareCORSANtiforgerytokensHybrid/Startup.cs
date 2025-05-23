﻿using Microsoft.Owin;
using Owin;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Linq;
using System.Net;
using MMiddleWareCORSANtiforgerytokensHybrid;
using System.IdentityModel.Tokens.Jwt;
using System;
using MiddleWareCORSANtiforgerytokensHybrid.API;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin;
using System.Configuration;
using System.Text;
using System.ServiceModel.Configuration;
using Microsoft.Owin.Security.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.ServiceModel.Security.Tokens;
using AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode;
[assembly: OwinStartup(typeof(Startup))]
public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        // Configuration JWT
        var secret = ConfigurationManager.AppSettings["jwtSettings:SecretKey"];
        var issuer = ConfigurationManager.AppSettings["jwtSettings:Issuer"];
        var audience = ConfigurationManager.AppSettings["jwtSettings:Audience"];

        app.UseJwtBearerAuthentication(
    new JwtBearerAuthenticationOptions
    {
        AuthenticationMode = AuthenticationMode.Active,
        AllowedAudiences = new[] { audience },
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true
        }
    });

        // Configuration Web API
        var config = new HttpConfiguration();
        WebApiConfig.Register(config);
        app.UseWebApi(config);
    }

    internal static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Enable CORS (configure appropriately for production)
            var cors = new EnableCorsAttribute(
                origins: "*",
                headers: "*",
                methods: "*"
            );
            config.EnableCors(cors);

            // Configure attribute routing
            config.MapHttpAttributeRoutes();

            // Convention-based routing
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            // Configure JSON formatter
            config.Formatters.JsonFormatter.SerializerSettings.Formatting =
                Newtonsoft.Json.Formatting.Indented;
            config.Formatters.JsonFormatter.SerializerSettings.ContractResolver =
                new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver();

            // Remove XML formatter (optional)
            config.Formatters.Remove(config.Formatters.XmlFormatter);

            // Configure error handling
            config.IncludeErrorDetailPolicy = IncludeErrorDetailPolicy.LocalOnly;

            // Enable HTTPS in production
#if !DEBUG
            config.Filters.Add(new RequireHttpsAttribute());
#endif

            // Add message handlers (like your AntiForgeryTokenHandler)
            config.MessageHandlers.Add(new JwtAntiForgeryTokenHandler());
        }
    }
}

public class JwtAntiForgeryTokenHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Skip validation for GET/HEAD/OPTIONS requests
        if (request.Method == HttpMethod.Get ||
            request.Method == HttpMethod.Head ||
            request.Method == HttpMethod.Options)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        try
        {
            // 1. Validate JWT from Authorization header
            var authHeader = request.Headers.Authorization;
            if (authHeader?.Scheme != "Bearer")
            {
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "Missing or invalid authorization header");
            }

            var jwtToken = authHeader.Parameter;
            var jwtValidator = new GenerateJwtTokenClass(
                issuer: "your-issuer",
                audience: "your-audience",
                tokenLifetime: TimeSpan.FromHours(1)
            );

            if (!jwtValidator.ValidateJwtToken(jwtToken, "your-secret-key"))
            {
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "Invalid JWT token");
            }

            // 2. Validate CSRF token from header
            if (!request.Headers.TryGetValues("X-CSRF-Token", out var csrfTokens))
            {
                return CreateErrorResponse(HttpStatusCode.Forbidden, "CSRF token missing");
            }

            var csrfToken = csrfTokens.FirstOrDefault();
            if (string.IsNullOrEmpty(csrfToken))
            {
                return CreateErrorResponse(HttpStatusCode.Forbidden, "Empty CSRF token");
            }

            // 3. Verify CSRF token matches the one in JWT
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = tokenHandler.ReadJwtToken(jwtToken);
            var jwtCsrfClaim = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == "csrf")?.Value;

            if (jwtCsrfClaim != csrfToken)
            {
                return CreateErrorResponse(HttpStatusCode.Forbidden, "Invalid CSRF token");
            }

            return await base.SendAsync(request, cancellationToken);
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(HttpStatusCode.InternalServerError, $"Security validation error: {ex.Message}");
        }
    }

    private HttpResponseMessage CreateErrorResponse(HttpStatusCode statusCode, string message)
    {
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(message),
            ReasonPhrase = message
        };
    }
}