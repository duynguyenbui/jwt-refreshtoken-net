using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SecureWebApi.Data;

public class AuthDbContext: IdentityDbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        var reader = "fec24d57-28d9-4e7b-8480-3878c35a8876";
        var writer = "9f88f84a-12b8-48bf-ae18-b4bd27c6eab6";

        var roles = new List<IdentityRole>
        {
            new IdentityRole()
            {
                Id = reader,
                ConcurrencyStamp = reader,
                Name = "Reader",
                NormalizedName = "Reader".ToUpper(),
            },
            new IdentityRole()
            {
                Id = writer,
                ConcurrencyStamp = writer,
                Name = "Writer",
                NormalizedName = "Writer".ToUpper(),
            }
        };
        foreach (var entityType in builder.Model.GetEntityTypes()) {
            var tableName = entityType.GetTableName ();
            if (tableName.StartsWith("AspNet")) {
                entityType.SetTableName (tableName.Substring(6));
            }
        }
        builder.Entity<IdentityRole>().HasData(roles);
    }

    public DbSet<RefreshToken> RefreshTokens { set; get; }
}