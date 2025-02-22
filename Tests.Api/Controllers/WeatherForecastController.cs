using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureJwt;
using Serilog;

namespace Tests_Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController(JwtTokenService jwtTokenService) : ControllerBase
    {
        [HttpGet]
        public string Get()
        {
            var tokenResponse = jwtTokenService.GenerateJwtToken("1");
            Log.Information("Token generated for user {Token}", tokenResponse.Token);
            Log.Information("Key Pub generated for user {PublicKey}", tokenResponse.PublicKey);
            return tokenResponse.Token;
        }


        [HttpPost]
        [Authorize]
        public IActionResult Post()
        {
            return Ok();
        }
    }
}
