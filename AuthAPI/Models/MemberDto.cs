using System.ComponentModel.DataAnnotations;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthAPI.Models;

public class MemberDto
{
    [Required]
    public int MemberId { get; set; }
    [Required]
    public string FullName { get; set; }
}