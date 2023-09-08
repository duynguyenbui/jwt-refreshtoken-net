using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SecureWebApi.Data;
using SecureWebApi.Dto;

namespace SecureWebApi.Repositories;

public class TokenRepository : ITokenRepository
{
    private readonly IConfiguration _configuration;
    private readonly AuthDbContext _authDbContext;
    private readonly UserManager<IdentityUser> _userManager;

    public TokenRepository(IConfiguration configuration, AuthDbContext authDbContext, UserManager<IdentityUser> userManager)
    {
        _configuration = configuration;
        _authDbContext = authDbContext;
        _userManager = userManager;
    }

    public TokenDto CreateJwtToken(IdentityUser user, List<string> roles)
    {
        // Create some claims
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("Id", user.Id),
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Audience"],
            claims,
            signingCredentials: credentials,
            expires: DateTime.Now.AddSeconds(10)
        );
        var refreshToken = CreateRefreshToken();
        var refreshTokenEntity = new RefreshToken()
        {
            Id = Guid.NewGuid(),
            JwtId = token.Id,
            Token = refreshToken,
            IsUsed = false,
            IsRevoked = false,
            IssueAt = DateTime.Now,
            ExpireAt = DateTime.Now.AddHours(1),
            UserId = user.Id,
        };
        _authDbContext.Add(refreshTokenEntity);
        _authDbContext.SaveChanges();

        return new TokenDto()
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken,
        };
    }

    public string CreateRefreshToken()
    {
        var random = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(random);

            return Convert.ToBase64String(random);
        }
    }

    public async Task<string> CheckCredentialToken(TokenDto tokenDto)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
        };
        try
        {
            // Check validate token format
            var tokenInVerification = jwtTokenHandler.ValidateToken(tokenDto.AccessToken,
                tokenValidationParameters, out var validatedToken);
            // Check Alg
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                if (!result)
                {
                    return "Something went wrong Alg";
                }
            }

            var value = tokenInVerification.Claims
                .FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Exp)
                ?.Value;
            if (value != null)
            {
                var expireTime = UnixTimeStampToDateTime(unixTimeStamp: long.Parse(value));
    
            
            
                if (expireTime > DateTime.Now)
                {
                    return "Something went wrong Expire Time";
                }
            }

            var storedToken =
                _authDbContext.RefreshTokens.FirstOrDefault(x => x.Token == tokenDto.RefreshToken);
            if (storedToken == null)
            {
                return "Something went wrong Database";
            }

            if (storedToken.IsUsed) return "Something went wrong is used";
            if (storedToken.IsRevoked) return "Something went wrong is revoked";

            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;
            
            if (storedToken.JwtId != jti)
            {
                return "Something went wrong in jwt Id";
            }

            storedToken.IsUsed = true;
            storedToken.IsRevoked = true;
            _authDbContext.Update(storedToken);
            _authDbContext.SaveChanges();
            var userId = tokenInVerification.Claims.FirstOrDefault(x => x.Type == "Id")?.Value;

            var user = await _userManager.FindByIdAsync(userId);
            var roleName = await _userManager.GetRolesAsync(user);
            var token = CreateJwtToken(user, roleName.ToList());
            return token.AccessToken!;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return "Something went wrong";
        }

    }
    
    private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
    {
        // Unix timestamp tính theo giây, nhưng hàm DateTime cần tính theo tick (1 tick = 100 nanosecond)
        DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long ticks = unixTimeStamp * TimeSpan.TicksPerSecond;
        return new DateTime(unixEpoch.Ticks + ticks, DateTimeKind.Utc);
    }
}