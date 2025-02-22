using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System;

namespace SecureJwt
{
    /// <summary>
    /// Provides extension methods for configuring JWT authentication services.
    /// </summary>
    public static class ServiceExtension
    {
        /// <summary>
        /// Gets or sets the JWT options for configuring token properties.
        /// </summary>
        internal static JwtConfiguration JwtOptions { get; set; } = new()
        {
            Config = new RotatingJwtOptions
            {
                RefreshTokenLifeTime = TimeSpan.FromMinutes(20),
                TokenLifeTime = TimeSpan.FromMinutes(20)
            },
            TokenValidationParameters = new TokenValidationParameters()
        };

        /// <summary>
        /// Configures rotating JWT authentication services.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="options">A function to configure JWT options.</param>
        /// <exception cref="ArgumentNullException">Thrown if the SecretKey is null or empty.</exception>
        public static void AddSecureJwt(this IServiceCollection services, Func<JwtConfiguration, JwtConfiguration> options)
        {
            JwtOptions = options.Invoke(new JwtConfiguration());

            if (string.IsNullOrEmpty(JwtOptions.Config.SecretKey))
            {
                throw new ArgumentNullException(nameof(JwtOptions.Config.SecretKey), "Secret provided is invalid.");
            }

            // Register necessary services in the dependency injection container.
            services.AddMemoryCache(); // ✅ Registers IMemoryCache in DI
            services.AddHttpContextAccessor(); // ✅ Registers IHttpContextAccessor in DI

            // Register the custom authentication scheme.
            services.AddAuthentication("SecureJwt")
                .AddScheme<AuthenticationSchemeOptions, CustomAuthenticationHandler>("SecureJwt", null);

            // Ensure the authentication scheme matches.
            services.AddAuthorizationBuilder()
                    // Ensure the authentication scheme matches.
                    .SetDefaultPolicy(new AuthorizationPolicyBuilder("SecureJwt")
                    .RequireAuthenticatedUser()
                    .Build());

            // Register the JWT token service as a singleton.
            services.AddSingleton<JwtTokenService>();

            // Log the token lifetime configuration.
            Log.Information("Tokens Lifetime configured to {TokenLifeTime}", JwtOptions.Config.TokenLifeTime);
        }
    }
}
