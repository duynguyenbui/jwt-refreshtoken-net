using System.ComponentModel.DataAnnotations;

namespace SecureWebApi.Dto;

public class RegisterRequestDto
{
    [Required]
    [DataType(DataType.EmailAddress)]
    public string Username { get; set; } = null!;

    [Required]
    [DataType(DataType.Password)]
    public string Password { set; get; } = null!;

    public string[] Roles { set; get; } = null!;
}