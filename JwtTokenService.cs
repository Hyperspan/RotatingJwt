using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

namespace RotatingJwt
{
    public class JwtTokenService
    {
        private readonly IMemoryCache _memoryCache;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public JwtTokenService(IMemoryCache memoryCache, IHttpContextAccessor httpContextAccessor)
        {
            _memoryCache = memoryCache;
            _httpContextAccessor = httpContextAccessor;
        }
        public TokenResponse GenerateAccessToken(string userId)
        {
            userId = userId.Encrypt(ServiceExtension.JwtOptions.SecretKey);
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                // Export private and public keys as XML strings
                var privateKeyXml = rsa.ToXmlString(true); // Contains private + public key
                var publicKeyXml = rsa.ToXmlString(false); // Only public key

                var key = new RsaSecurityKey(rsa);
                var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
                if (!ServiceExtension.JwtOptions.Claims.Exists(x => x.Type == ClaimTypes.Authentication))
                {
                    ServiceExtension.JwtOptions.Claims.Add(new Claim(ClaimTypes.Authentication, userId));
                }
                else
                {
                    var index = ServiceExtension.JwtOptions.Claims.FindIndex(x => x.Type == ClaimTypes.Authentication);
                    ServiceExtension.JwtOptions.Claims[index] = new Claim(ClaimTypes.Authentication, userId);
                }

                var token = new JwtSecurityToken(
                    issuer: ServiceExtension.JwtOptions.Issuer,
                    audience: ServiceExtension.JwtOptions.Audience,
                    claims: ServiceExtension.JwtOptions.Claims,
                    expires: DateTime.UtcNow.Add(ServiceExtension.JwtOptions.TokenLifeTime),
                    signingCredentials: credentials
                );



                var response = new TokenResponse
                {
                    PrivateKey = privateKeyXml.Encrypt(ServiceExtension.JwtOptions.SecretKey),
                    PublicKey = publicKeyXml.Encrypt(ServiceExtension.JwtOptions.SecretKey),
                    Token = new JwtSecurityTokenHandler().WriteToken(token)
                };

                _memoryCache.Set(userId, response, ServiceExtension.JwtOptions.TokenLifeTime);
                return response;
            }
        }

        public TokenValidationParameters ValidateParameters()
        {
            var token = _httpContextAccessor.HttpContext?.Request.Headers["Authorization"].ToString()
                .Replace("Bearer ", "") ?? "";
            //?? throw new NullReferenceException("Unable to read the token");
            return ValidateParameters(token);
        }

        public TokenValidationParameters ValidateParameters(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true
                };
            }
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                var handler = new JwtSecurityTokenHandler();

                // Read and parse the token
                var jwtToken = handler.ReadJwtToken(token);

                // Extract the claim value
                var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Authentication)?.Value;

                var tokenResponse =
                    _memoryCache.Get<TokenResponse>(userId ??
                                                    throw new NullReferenceException("Authentication Claim is null"))
                    ?? throw new NullReferenceException("Token Response not found or expired");

                rsa.FromXmlString(tokenResponse.PublicKey.Decrypt(ServiceExtension.JwtOptions.SecretKey));

                var key = new RsaSecurityKey(rsa);

                return new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key
                };
            }
        }
    }
}