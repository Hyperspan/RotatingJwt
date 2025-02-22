namespace SecureJwt
{
    /// <summary>
    /// Represents the response containing the generated JWT token and associated keys.
    /// </summary>
    public class TokenResponse
    {
        /// <summary>
        /// Gets or sets the JWT access token.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the encrypted public key used for token validation.
        /// </summary>
        public string PublicKey { get; set; }
    }
}