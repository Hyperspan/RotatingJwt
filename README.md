---
# RamsonDevelopers.SecureJwt

RamsonDevelopers.SecureJwt is a .NET class library that provides functionality to Securely authenticate using JWT, by ensuring the signing keys are rotated and by implementing fingerprint validation layer to it as well.
---

## Installation

To use **RamsonDevelopers.SecureJwt** in your project, follow these steps:

1. Download the **RamsonDevelopers.SecureJwt** source code or add it as a NuGet package to your solution.

2. Add a reference to the **AddSecureJwt()** Method in **RamsonDevelopers.SecureJwt** project or the installed NuGet package in your target project's **program.cs**.

```csharp

builder.Services.AddSecureJwt(options =>
{
    options.Config = new RotatingJwtOptions
   {
      TokenLifeTime = TimeSpan.FromMinutes(20),
      RefreshTokenLifeTime = TimeSpan.FromMinutes(40),
      AesKeySize = 256,
      Audience = "https://localhost:7054/",
      Issuer = "https://localhost:7054/",
   };

   // Create a random AES
    using var aes = Aes.Create();
    aes.KeySize = 256;
    aes.GenerateKey();

    // Or can use any custom AES key can be from key vault
    options.Config.SecretKey = Convert.ToBase64String(aes.Key);
    options.Config.AesKeySize = aes.KeySize;
    return options;
});
```

---

_NOTE: you dont need to have the following lines in the program.cs file:_

```csharp
     builder.Services.AddAuthentication(authentication =>
        {
            authentication.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            authentication.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(bearer =>{
            // Code here
        });
```

---

## Usage

To create tokens using **RamsonDevelopers.SecureJwt**, follow these steps:

```csharp
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

```

---

## Credits

**RamsonDevelopers.SecureJwt** was developed by [Ayush Aher](https://ayush.ramson-developers.com) and is maintained by **Ramson Developers**. We would like to acknowledge the contributions of the open-source community and express our gratitude to all the contributors who helped make this project possible.

---

## Feedback

If you have any feedback, please reach out to us at [ayushaher118@gmail.com](mailto:ayushaher118@gmail.com)
or [Raise a Issue](https://github.com/Hyperspan/RotatingJwt/issues) in [Github Repository](https://github.com/Hyperspan/RotatingJwt)
