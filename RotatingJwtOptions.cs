using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace RotatingJwt
{
    public class RotatingJwtOptions
    {
        public int AesKeySize { get; set; } = 256;
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public List<Claim> Claims { get; set; } = new List<Claim>();
        public string SecretKey { get; set; }
        public TimeSpan TokenLifeTime { get; set; }
        public TimeSpan RefreshTokenLifeTime { get; set; }
    }
}