using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Models;

public class PersonalTrainerDto
{
    [Required]
    public int TrainerId { get; set; }
    [Required]
    public string Name { get; set; }
}