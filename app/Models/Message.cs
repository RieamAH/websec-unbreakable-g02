using System.ComponentModel.DataAnnotations;

namespace Unbreakable.Models;

// Opdracht 3: de server kent enkel de versleutelde tekst.
// Het bericht wordt in de browser versleuteld (one-time pad, modulo 37) en
// krijgt een HMAC-SHA256. Het onderwerp is geschrapt: dat zou anders als
// leesbare tekst in de databank staan.
public class Message
{
    public int Id { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Van")]
    public string Sender { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Aan")]
    public string Recipient { get; set; }

    // Ciphertext: enkel de 37 tekens A-Z, 0-9 en _, maximaal 40 (de lengte van een codeboeklijn).
    [Required]
    [StringLength(40, MinimumLength = 1)]
    [RegularExpression("^[A-Z0-9_]+$", ErrorMessage = "De ciphertext bevat enkel A-Z, 0-9 en _.")]
    [Display(Name = "Ciphertext")]
    public string Body { get; set; }

    // Nummer van de lijn in het codeboek. Nooit de sleutel zelf.
    [Range(1, 9999)]
    [Display(Name = "Lijn in het codeboek")]
    public int KeyLine { get; set; }

    // HMAC-SHA256 als hex (32 bytes = 64 tekens).
    [Required]
    [RegularExpression("^[0-9a-f]{64}$", ErrorMessage = "De MAC is 64 hexadecimale tekens.")]
    [Display(Name = "MAC")]
    public string Mac { get; set; }

    [Display(Name = "Verzonden")]
    public DateTime SentAt { get; set; }
}
