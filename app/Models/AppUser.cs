using System.ComponentModel.DataAnnotations;

namespace Unbreakable.Models;

// Opdracht 4: wie ooit heeft ingelogd. Nodig om een ontvanger op naam
// (preferred_username) om te zetten naar zijn vaste id (sub) in OpenFGA.
// Dit is een adresboek, geen autorisatie: wat iemand mag, staat in OpenFGA.
public class AppUser
{
    // De claim "sub" uit het token: uniek en onveranderlijk binnen de realm.
    [Key]
    [StringLength(64)]
    public string Sub { get; set; }

    // De claim "preferred_username": enkel om te tonen en om te adresseren.
    [Required]
    [StringLength(40)]
    public string Username { get; set; }

    public DateTime LastSeen { get; set; }
}
