using Microsoft.AspNetCore.Identity;
using SecureWebApi.Dto;

namespace SecureWebApi.Repositories;

public interface ITokenRepository
{
    TokenDto CreateJwtToken(IdentityUser user, List<string> roles);

    string CreateRefreshToken();

    Task<string> CheckCredentialToken(TokenDto tokenDto);
}