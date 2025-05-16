using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using System.Web.Http.Cors;

namespace MiddleWareCORSANtiforgerytokensHybrid.API
{
    [EnableCors(origins: "*", headers: "*", methods: "*")] // À configurer proprement en prod
    public class AuthController : ApiController
    {
        private readonly IUserService _userService;
        private readonly string _jwtSecret;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;

        public AuthController(IUserService userService)
        {
            _userService = userService;
            _jwtSecret = "your-256-bit-secret-key"; // À mettre dans Web.config
            _jwtIssuer = "your-issuer";
            _jwtAudience = "your-audience";
        }

        [HttpPost]
        [Route("api/auth/login")]
        public HttpResponseMessage Login([FromBody] LoginModel model)
        {
            try
            {
                // Validation
                if (model == null || string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest,
                        new { Message = "Username et password requis" });
                }

                // Authentification
                var user = _userService.Authenticate(model.Username, model.Password);
                if (user == null)
                {
                    return Request.CreateResponse(HttpStatusCode.Unauthorized,
                        new { Message = "Identifiants invalides" });
                }

                // Génération des tokens
                var tokenResult = GenerateTokens(user.Id, user.Roles);

                // Réponse
                return Request.CreateResponse(HttpStatusCode.OK, new
                {
                    AccessToken = tokenResult.AccessToken,
                    CsrfToken = tokenResult.CsrfToken,
                    ExpiresIn = 3600 // 1 heure
                });
            }
            catch (Exception ex)
            {
                // Loguer l'erreur
                return Request.CreateResponse(HttpStatusCode.InternalServerError,
                    new { Message = "Erreur lors de l'authentification" });
            }
        }

        private (string AccessToken, string CsrfToken) GenerateTokens(string userId, string[] roles)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var csrfToken = Guid.NewGuid().ToString("N");

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("csrf", csrfToken),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64)
            }.Concat(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var token = new JwtSecurityToken(
                issuer: _jwtIssuer,
                audience: _jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return (new JwtSecurityTokenHandler().WriteToken(token), csrfToken);
        }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public interface IUserService
    {
        User Authenticate(string username, string password);
    }

    public class User
    {
        public string Id { get; set; }
        public string[] Roles { get; set; } = new string[0];
    }
}