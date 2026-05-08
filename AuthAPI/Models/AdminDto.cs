using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Models;

public class AdminDto
{
    [Required]
    public int AdminId { get; set; }
    [Required]
    public string Username { get; set; }
}