using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace SecureWebApi.Data;

[Table("RefreshToken")]
public class RefreshToken
{
    [Key]
    public Guid Id { set; get; }
    
    public string UserId { set; get; }
    [ForeignKey(nameof(UserId))] 
    public IdentityUser User { set; get; }

    public string Token { get; set; }
    public string JwtId { set; get; }
    
    public bool IsUsed { set; get; }
    public bool IsRevoked { set; get; }
    public DateTime IssueAt { set; get; }
    public DateTime ExpireAt { set; get; }
}