using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthAPI.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace AuthAPI.Token;

public class TokenProvider : ITokenProvider
{
    private readonly IConfiguration configuration;
    
    public TokenProvider(IConfiguration configuration)
    {
        this.configuration = configuration;
    }
    
    public string CreateMemberToken(MemberDto member)
    {
        string secretKey = Environment.GetEnvironmentVariable("JWT_SECRET");
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var tokenDescription = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, member.MemberId.ToString()),
                new Claim(JwtRegisteredClaimNames.Name, member.FullName),
                new Claim(JwtRegisteredClaimNames.Typ, member.MemberSubscriptionId.ToString())
            ]),
            Expires = DateTime.UtcNow.AddMinutes(configuration.GetValue<int>("Jwt:ExpirationInMinutes")),
            SigningCredentials =  credentials,
            Issuer = configuration.GetValue<string>("Jwt:Issuer"),
            Audience = configuration.GetValue<string>("Jwt:Audience")
        };

        var handler = new JsonWebTokenHandler();

        string token = handler.CreateToken(tokenDescription);
        
        return token;
    }
    
    public string CreatePersonalTrainerToken(PersonalTrainerDto trainer)
    {
        string secretKey = Environment.GetEnvironmentVariable("JWT_SECRET");
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var tokenDescription = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, trainer.TrainerId.ToString()),
                new Claim(JwtRegisteredClaimNames.Name, trainer.Name)
            ]),
            Expires = DateTime.UtcNow.AddMinutes(configuration.GetValue<int>("Jwt:ExpirationInMinutes")),
            SigningCredentials =  credentials,
            Issuer = configuration.GetValue<string>("Jwt:Issuer"),
            Audience = configuration.GetValue<string>("Jwt:Audience")
        };

        var handler = new JsonWebTokenHandler();

        string token = handler.CreateToken(tokenDescription);
        
        return token;
    }
    
    public string CreateAdminToken(AdminDto admin)
    {
        string secretKey = Environment.GetEnvironmentVariable("JWT_SECRET");
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var tokenDescription = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, admin.AdminId.ToString()),
                new Claim(JwtRegisteredClaimNames.PreferredUsername, admin.Username)
            ]),
            Expires = DateTime.UtcNow.AddMinutes(configuration.GetValue<int>("Jwt:ExpirationInMinutes")),
            SigningCredentials =  credentials,
            Issuer = configuration.GetValue<string>("Jwt:Issuer"),
            Audience = configuration.GetValue<string>("Jwt:Audience")
        };

        var handler = new JsonWebTokenHandler();

        string token = handler.CreateToken(tokenDescription);
        
        return token;
    }

    // Returns -1 if no userId found in webtoken
    // Rerurns 0 if failed to parse the userId from webtoken
    public int GetUserId(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var decodedToken = handler.ReadJwtToken(token);

        var userId = decodedToken.Subject;
        if (userId == null)
            return -1;
        
        int.TryParse(userId, out int result);
        return result;
    }
}