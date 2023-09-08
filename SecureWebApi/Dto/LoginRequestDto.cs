using System.ComponentModel.DataAnnotations;

namespace SecureWebApi.Dto;

public class LoginRequestDto
{
    [Required]
    [DataType(DataType.EmailAddress)]
    public string Username { get; set; } = null!;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = null!;
}