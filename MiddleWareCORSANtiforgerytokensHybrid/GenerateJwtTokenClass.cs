using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Cors;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Owin;

namespace MMiddleWareCORSANtiforgerytokensHybrid
{
    public class GenerateJwtTokenClass
    {
        private readonly string _issuer;
        private readonly string _audience;
        private readonly TimeSpan _tokenLifetime;

        public GenerateJwtTokenClass(string issuer, string audience, TimeSpan tokenLifetime)
        {
            _issuer = issuer;
            _audience = audience;
            _tokenLifetime = tokenLifetime;
        }

        public string GenerateJwtToken(string userId, string secretKey)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, GenerateCryptographicallySecureGuid()),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("csrf", GenerateAntiForgeryToken()) // Embed CSRF token in JWT
            };

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.Add(_tokenLifetime),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public bool ValidateJwtToken(string token, string secretKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _issuer,
                    ValidateAudience = true,
                    ValidAudience = _audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private string GenerateCryptographicallySecureGuid()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[16];
                rng.GetBytes(bytes);
                return new Guid(bytes).ToString();
            }
        }

        private string GenerateAntiForgeryToken()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);
                return Convert.ToBase64String(tokenData);
            }
        }
    }

}