using Microsoft.OpenApi.Models;
using SecureJwt;
using System.Security.Cryptography;

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
                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateKey();
                options.Config.SecretKey = Convert.ToBase64String(aes.Key);
                return options;
            });

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
