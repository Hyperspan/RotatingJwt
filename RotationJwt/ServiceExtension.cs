using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using System;
using System.Text;

namespace RotatingJwt
{
    public static class ServiceExtension
    {
        internal static RotatingJwtOptions JwtOptions { get; set; } = new RotatingJwtOptions
        {
            RefreshTokenLifeTime = TimeSpan.FromMinutes(40),
            TokenLifeTime = TimeSpan.FromMinutes(20)
        };

        public static void AddRotatingJwt(this IServiceCollection services, Func<RotatingJwtOptions, RotatingJwtOptions> options)
        {
            JwtOptions = options.Invoke(new RotatingJwtOptions());

            if (string.IsNullOrEmpty(JwtOptions.SecretKey))
            {
                throw new ArgumentNullException(nameof(JwtOptions.SecretKey), "Secret provided is invalid.");
            }

            JwtOptions.SecretKey = JwtOptions.SecretKey;
            services.AddMemoryCache(); // ✅ Registers IMemoryCache in DI
            services.AddSingleton(typeof(JwtTokenService));
            Log.Information("Tokens Lifetime configured to {tokenLifeTime}", JwtOptions.TokenLifeTime);
        }


        /// <summary>
        /// Converts a byte array to a hex string.
        /// </summary>
        public static string ByteArrayToHexString(this byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }
}

