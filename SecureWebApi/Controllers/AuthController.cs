using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecureWebApi.Dto;
using SecureWebApi.Repositories;

namespace SecureWebApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ITokenRepository _tokenRepository;

    public AuthController(UserManager<IdentityUser> userManager, ITokenRepository tokenRepository)
    {
        _userManager = userManager;
        _tokenRepository = tokenRepository;
    }


    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto registerRequestDto)
    {
        var identityUser = new IdentityUser()
        {
            UserName = registerRequestDto.Username,
            Email = registerRequestDto.Username,
        };
        var identityResult =  await _userManager.CreateAsync(identityUser, registerRequestDto.Password);

        if (identityResult.Succeeded)
        {
            // Add roles to this user
            if (registerRequestDto.Roles is not null)
            {
                identityResult = await _userManager.AddToRolesAsync(identityUser, registerRequestDto.Roles);
                if (identityResult.Succeeded)
                {
                    return Ok("User was register successfully");
                }
            }
        }

        return BadRequest("Something went wrong");
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
    {
        var user = await _userManager.FindByEmailAsync(loginRequestDto.Username);

        if (user != null)
        {
            var result = await _userManager.CheckPasswordAsync(user, loginRequestDto.Password);
            if (result)
            {
                var roles = await _userManager.GetRolesAsync(user);

                if (roles is not null)
                {
                    var tokenDto = _tokenRepository.CreateJwtToken(user, roles.ToList()); 
                    return Ok(tokenDto);
                }
            }
        }
        return BadRequest("Something went wrong!");
    }

    [HttpPost]
    [Route("RefreshToken")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenDto tokenDto)
    {
        return Ok(await _tokenRepository.CheckCredentialToken(tokenDto));

    }
}


