using System.Diagnostics;
using AuthAPI.Models;
using AuthAPI.Token;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly ITokenProvider _tokenProvider;

    public AuthController(ITokenProvider tokenProvider, ILogger<AuthController> logger)
    {
        _logger = logger;
        _tokenProvider = tokenProvider;
    }
    
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [Route("member")]
    public IActionResult AuthorizeMember([FromBody]MemberDto member)
    {
        if (member.MemberId <= 0 || string.IsNullOrWhiteSpace(member.FullName))
        {
            return BadRequest("MemberId and MemberSubscriptionId cannot be less than 1");
        }
        _logger.LogInformation($"Calling {nameof(AuthorizeMember)} endpoint for member: {member.FullName}");
        var tokenString = _tokenProvider.CreateMemberToken(member);
        if (string.IsNullOrWhiteSpace(tokenString))
        {
            _logger.LogError($"{nameof(AuthorizePersonalTrainer)} returned empty string");
            return Unauthorized();
        }
        _logger.LogInformation($"Returning JWT token for user: {member.FullName}");
        return Ok(tokenString);
    }
    
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [Route("trainer")]
    public IActionResult AuthorizePersonalTrainer([FromBody]PersonalTrainerDto trainer)
    {
        if (trainer.TrainerId <= 0 || string.IsNullOrWhiteSpace(trainer.Name))
        {
            return BadRequest("TrainerId cannot be less than 1");
        }
        _logger.LogInformation($"Calling {nameof(AuthorizePersonalTrainer)} endpoint for Personal Trainer: {trainer.Name}");
        var tokenString = _tokenProvider.CreatePersonalTrainerToken(trainer);
        if (string.IsNullOrWhiteSpace(tokenString))
        {
            _logger.LogError($"{nameof(AuthorizePersonalTrainer)} returned empty string");
            return Unauthorized();
        }
        _logger.LogInformation($"Returning JWT token for Personal Trainer: {trainer.Name}");
        return Ok(tokenString);
    }
    
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [Route("admin")]
    public IActionResult AuthorizeAdmin([FromBody]AdminDto admin)
    {
        if (admin.AdminId <= 0 || string.IsNullOrWhiteSpace(admin.Username))
        {
            return BadRequest("AdminId cannot be less than 1");
        }
        _logger.LogInformation($"Calling {nameof(AuthorizeAdmin)} endpoint for Admin with id: {admin.AdminId}");
        var tokenString = _tokenProvider.CreateAdminToken(admin);
        if (string.IsNullOrWhiteSpace(tokenString))
        {
            _logger.LogError($"{nameof(AuthorizeAdmin)} returned empty string");
            return Unauthorized();
        }
        _logger.LogInformation($"Returning JWT token for Admin with id: {admin.AdminId}");
        return Ok(tokenString);
    }
    
}
