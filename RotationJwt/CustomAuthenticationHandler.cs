using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecureJwt;

/// <summary>
/// Custom authentication handler for JWT-based authentication with fingerprinting.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="CustomAuthenticationHandler"/> class.
/// </remarks>
/// <param name="jwtTokenService">The JWT token service.</param>
/// <param name="options">The authentication scheme options.</param>
/// <param name="logger">The logger factory.</param>
/// <param name="encoder">The URL encoder.</param>
public class CustomAuthenticationHandler(JwtTokenService jwtTokenService,
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private readonly JwtTokenService _jwtTokenService = jwtTokenService;

    /// <summary>
    /// Handles the authentication process.
    /// </summary>
    /// <returns>The authentication result.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authHeader = Context.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Generate fingerprint for the request
        var fingerprint = GenerateFingerprint(Context);

        // Store fingerprint in HttpContext for later use
        Context.Items["ClientFingerprint"] = fingerprint;

        var token = authHeader["Bearer ".Length..].Trim();
        var result = _jwtTokenService.VerifyToken(token);

        if (!result.IsValid) return Task.FromResult(AuthenticateResult.Fail("Invalid Token"));
        var ticket = new AuthenticationTicket(result.ClaimsPrincipal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    /// <summary>
    /// Handles unauthorized access challenge.
    /// </summary>
    /// <param name="properties">Authentication properties.</param>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Response.WriteAsync("Unauthorized");
    }

    /// <summary>
    /// Handles forbidden access scenarios.
    /// </summary>
    /// <param name="properties">Authentication properties.</param>
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Response.WriteAsync("Forbidden");
    }

    /// <summary>
    /// Generates a fingerprint for the client request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A Base64-encoded SHA256 hash of request details.</returns>
    private static string GenerateFingerprint(HttpContext context)
    {
        var userAgent = context.Request.Headers.UserAgent.FirstOrDefault() ?? "UnknownUA";
        var acceptLang = context.Request.Headers.AcceptLanguage.FirstOrDefault() ?? "UnknownLang";
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "UnknownIP";
        var rawData = $"{userAgent}-{acceptLang}-{ipAddress}";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));
        return Convert.ToBase64String(hashBytes);
    }
}
