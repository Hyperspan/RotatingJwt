using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RotatingJwt;
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
            var tokenResponse = jwtTokenService.GenerateAccessToken("1");

            Log.Information("Token generated for user {userId}", tokenResponse.Token);  
            Log.Information("Key Pvt generated for user {userId}", tokenResponse.PrivateKey);  
            Log.Information("Key Pub generated for user {userId}", tokenResponse.PublicKey);

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
