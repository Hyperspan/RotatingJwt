namespace RotatingJwt
{
    public class TokenResponse
    {
        public string Token { get; set; }
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }
}