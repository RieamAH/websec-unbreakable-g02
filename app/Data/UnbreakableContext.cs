using Microsoft.EntityFrameworkCore;
using Unbreakable.Models;

namespace Unbreakable.Data;

public class UnbreakableContext : DbContext
{
    public UnbreakableContext(DbContextOptions<UnbreakableContext> options)
        : base(options)
    {
    }

    public DbSet<Message> Messages { get; set; }

    public DbSet<AppUser> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Een gebruikersnaam hoort bij precies één account (Keycloak: "edit
        // username" staat uit). Zo kan een bericht nooit bij twee mensen landen.
        modelBuilder.Entity<AppUser>().HasIndex(u => u.Username).IsUnique();
    }
}
