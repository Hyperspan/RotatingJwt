
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RotatingJwt;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.OpenApi.Models;

namespace Tests_Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API", Version = "v1" });

                // Configure JWT authentication for Swagger
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Enter 'Bearer {your JWT token}'"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new List<string>()
                    }
                });
            });

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddRotatingJwt(options =>
            {
                options.TokenLifeTime = TimeSpan.FromMinutes(20);
                options.RefreshTokenLifeTime = TimeSpan.FromMinutes(40);
                options.AesKeySize = 256;
                options.Audience = "http://localhost:5281";
                options.Issuer = "http://localhost:5281";
                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateKey();
                options.SecretKey = Convert.ToBase64String(aes.Key);
                return options;
            });

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    using (var rsa = new RSACryptoServiceProvider(2048))
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = false,  // Will be validated dynamically
                            ValidateAudience = false,
                            ValidateIssuerSigningKey = true,
                            ValidateLifetime = false, // Will be validated dynamically
                            IssuerSigningKey = new RsaSecurityKey(rsa) // Temporary dummy key
                        };
                    }
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {
                            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
                            if (!string.IsNullOrEmpty(token))
                            {
                                context.HttpContext.Items["JWT"] = token;
                            }


                            try
                            {
                                var serviceProvider = context.HttpContext.RequestServices;
                                var jwtService = serviceProvider.GetRequiredService<JwtTokenService>();

                                if (string.IsNullOrEmpty(token))
                                {
                                    context.Fail("JWT Token is missing.");
                                    return Task.CompletedTask;
                                }

                                // ?? Dynamically fetch validation parameters
                                var validationParameters = jwtService.ValidateParameters(token);
                                var handler = new JwtSecurityTokenHandler();

                                // ?? Revalidate token with updated parameters
                                handler.ValidateToken(token, validationParameters, out _);
                            }
                            catch (SecurityTokenException ex)
                            {
                                context.Fail($"Token validation failed: {ex.Message}");
                            }
                            catch (Exception ex)
                            {
                                context.Fail($"Unexpected error: {ex.Message}");
                            }
                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            Console.WriteLine($"Authentication Failed: {context.Exception.Message}");
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = async context =>
                        {
                            try
                            {
                                var serviceProvider = context.HttpContext.RequestServices;
                                var jwtService = serviceProvider.GetRequiredService<JwtTokenService>();

                                var token = context.HttpContext.Items["JWT"] as string;
                                if (string.IsNullOrEmpty(token))
                                {
                                    context.Fail("JWT Token is missing.");
                                    return;
                                }

                                // ?? Dynamically fetch validation parameters
                                var validationParameters = jwtService.ValidateParameters(token);
                                var handler = new JwtSecurityTokenHandler();

                                // ?? Revalidate token with updated parameters
                                handler.ValidateToken(token, validationParameters, out _);
                            }
                            catch (SecurityTokenException ex)
                            {
                                context.Fail($"Token validation failed: {ex.Message}");
                            }
                            catch (Exception ex)
                            {
                                context.Fail($"Unexpected error: {ex.Message}");
                            }
                        }
                    };
                });


            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
