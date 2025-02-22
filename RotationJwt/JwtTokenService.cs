using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecureJwt
{
    /// <summary>
    /// Service for generating and validating JWT tokens with fingerprinting.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="JwtTokenService"/> class.
    /// </remarks>
    /// <param name="memoryCache">The memory cache instance.</param>
    /// <param name="httpContextAccessor">The HTTP context accessor.</param>
    public class JwtTokenService(IMemoryCache memoryCache, IHttpContextAccessor httpContextAccessor)
    {
        private readonly IMemoryCache _memoryCache = memoryCache;
        private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

        /// <summary>
        /// Generates an access token for the given user ID.
        /// </summary>
        /// <param name="userId">The user ID to encode into the token.</param>
        /// <param name="claims">The user ID to encode into the token.</param>
        /// <returns>A <see cref="TokenResponse"/> containing the generated token and keys.</returns>
        public TokenResponse GenerateJwtToken(string userId, List<Claim> claims = null)
        {
            using var rsa = new RSACryptoServiceProvider(4096);
            return GenerateJwtToken(userId, rsa, claims);
        }

        /// <summary>
        /// Generates an access token for the given user ID.
        /// </summary>
        /// <param name="userId">The user ID to encode into the token.</param>
        /// <param name="claims">The claims, user should have in the generated token.</param>
        /// <param name="rsaKey">The RSA Key Service Provider, which will create key to be used for signing the token.</param>
        /// <returns>A <see cref="TokenResponse"/> containing the generated token and keys.</returns>
        public TokenResponse GenerateJwtToken(string userId, RSACryptoServiceProvider rsaKey, List<Claim> claims = null)
        {
            userId = userId.Encrypt(ServiceExtension.JwtOptions.Config.SecretKey);
            // Export private and public keys
            var privateKeyXml = rsaKey.ToXmlString(true);
            var publicKeyXml = rsaKey.ToXmlString(false);

            var key = new RsaSecurityKey(rsaKey);
            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            // Generate fingerprint from request headers
            var fingerprint = GenerateFingerprint();

            // Add userId and fingerprint to claims
            claims ??= [];

            claims.AddRange([
                new Claim(ClaimTypes.Authentication, userId),
                new Claim("fingerprint", fingerprint) // Custom claim for fingerprint
            ]);

            var token = new JwtSecurityToken(
                issuer: ServiceExtension.JwtOptions.Config.Issuer,
                audience: ServiceExtension.JwtOptions.Config.Audience,
                claims: claims,
                expires: DateTime.UtcNow.Add(ServiceExtension.JwtOptions.Config.TokenLifeTime),
                signingCredentials: credentials
            );

            var response = new TokenResponse
            {
                PublicKey = publicKeyXml.Encrypt(ServiceExtension.JwtOptions.Config.SecretKey),
                Token = new JwtSecurityTokenHandler().WriteToken(token)
            };

            // Store token response in memory cache along with fingerprint
            _memoryCache.Set(userId, new { response, fingerprint }, ServiceExtension.JwtOptions.Config.TokenLifeTime);
            return response;
        }

        /// <summary>
        /// Validates the token extracted from the HTTP request.
        /// </summary>
        /// <returns>A <see cref="TokenValidationResult"/> representing the validation outcome.</returns>
        public TokenValidationResult VerifyToken()
        {
            var token = _httpContextAccessor.HttpContext?.Request.Headers["Authorization"].ToString()
                .Replace("Bearer ", "") ?? "";

            return VerifyToken(token);
        }

        /// <summary>
        /// Validates a given JWT token.
        /// </summary>
        /// <param name="token">The JWT token to validate.</param>
        /// <returns>A <see cref="TokenValidationResult"/> representing the validation outcome.</returns>
        public TokenValidationResult VerifyToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return new TokenValidationResult { IsValid = false, Error = "Token is missing" };
            }

            using var rsa = new RSACryptoServiceProvider(4096);
            var handler = new JwtSecurityTokenHandler();

            // Read and parse the token
            var jwtToken = handler.ReadJwtToken(token);

            // Extract claims
            var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Authentication)?.Value;
            var tokenFingerprint = jwtToken.Claims.FirstOrDefault(c => c.Type == "fingerprint")?.Value;

            if (!_memoryCache.TryGetValue(userId, out var cachedTokenObj))
            {
                return new TokenValidationResult { IsValid = false, Error = "Invalid or expired token" };
            }

            var cachedTokenData = (dynamic)cachedTokenObj;
            var cachedFingerprint = cachedTokenData?.fingerprint;

            // Compare fingerprint from token with request fingerprint
            var requestFingerprint = GenerateFingerprint();
            if (tokenFingerprint != requestFingerprint != cachedFingerprint)
            {
                return new TokenValidationResult
                { IsValid = false, Error = "Fingerprint mismatch! Possible token reuse." };
            }

            if (cachedTokenData.response is not TokenResponse tokenResponse)
            {
                return new TokenValidationResult { IsValid = false, Error = "Invalid token data" };
            }

            rsa.FromXmlString(tokenResponse.PublicKey.Decrypt(ServiceExtension.JwtOptions.Config.SecretKey));
            var key = new RsaSecurityKey(rsa);

            var parameters = ServiceExtension.JwtOptions.TokenValidationParameters;

            parameters.IssuerSigningKey = key;

            var principal = handler.ValidateToken(token, parameters, out _);
            return new TokenValidationResult { IsValid = true, ClaimsPrincipal = principal };
        }

        /// <summary>
        /// Generates a fingerprint based on client request data.
        /// </summary>
        /// <returns>A Base64-encoded SHA256 hash representing the request fingerprint.</returns>
        private string GenerateFingerprint()
        {
            var context = _httpContextAccessor.HttpContext;
            var userAgent = context?.Request.Headers.UserAgent.FirstOrDefault() ?? "UnknownUA";
            var acceptLang = context?.Request.Headers.AcceptLanguage.FirstOrDefault() ?? "UnknownLang";
            var ipAddress = context?.Connection.RemoteIpAddress?.ToString() ?? "UnknownIP";
            var rawData = $"{userAgent}-{acceptLang}-{ipAddress}";
            var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));
            return Convert.ToBase64String(hashBytes);
        }
    }
}
