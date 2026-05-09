using AuthAPI.Controllers;
using AuthAPI.Models;
using AuthAPI.Token;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using NLog;

namespace AuthAPI.UnitTest;

[TestClass]
public sealed class AuthControllerTests
{
    Mock<ILogger<AuthController>> _logger;
    Mock<ITokenProvider> _tokenProviderMock;
    TokenProvider _tokenProvider;
    AuthController _authController;
    
    [TestInitialize]
    public void Setup()
    {
        // Should mirror appsettings.json in 'AuthAPI'
        var configRoot = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Jwt:ExpirationInMinutes", "30" },
                { "Jwt:Issuer", "AuthService" },
                { "Jwt:Audience", "User" },
            })
            .Build();
        
        Environment.SetEnvironmentVariable("JWT_SECRET", "randomAssvariablefortesting#&€&#&#%&#€&REGWFG/(/(/");
        
        _logger = new Mock<ILogger<AuthController>>();
        _tokenProviderMock = new Mock<ITokenProvider>();
        _tokenProvider = new TokenProvider(configRoot);
        _authController = new AuthController(_tokenProvider, _logger.Object);
    }
    
    [TestMethod]
    public void CreateMemberToken_returns_200OKObjectResult_and_token_on_valid_memberDTO()
    {
        // Arrange
        MemberDto dto = new MemberDto()
        {
            MemberId = 1,
            FullName = "John Doe",
            MemberSubscriptionId = 3
        };

        // Act
        
        var result = _authController.AuthorizeMember(dto);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        
        var token = result as OkObjectResult;
        Assert.IsNotNull(token);
        Assert.IsInstanceOfType(token.Value, typeof(string));
    }
    
    [TestMethod]
    public void CreateMemberToken_returns_400badrequestresult_on_malformed_request()
    {
        // Arrange
        MemberDto dto = new MemberDto()
        {
            MemberId = 1,
            MemberSubscriptionId = 3
        };

        // Act
        
        var result = _authController.AuthorizeMember(dto);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(BadRequestObjectResult));
    }
    
    [TestMethod]
    public void CreateMemberToken_returns_401unauthorizedresult_on_token_creation_failure()
    {
        // Arrange
        _authController = new AuthController(_tokenProviderMock.Object, _logger.Object);
        _tokenProviderMock.Setup(provider => provider.CreateMemberToken(It.IsAny<MemberDto>()))
            .Returns(string.Empty);
        MemberDto dto = new MemberDto()
        {
            MemberId = 1,
            FullName = "John Doe",
            MemberSubscriptionId = 3
        };

        // Act
        
        var result = _authController.AuthorizeMember(dto);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
    }
    
    [TestMethod]
    public void CreatePersonalTrainerToken_returns_200OKObjectResult_and_token_on_valid_personaltrainerDTO()
    {
        // Arrange
        PersonalTrainerDto dto = new PersonalTrainerDto()
        {
            Name = "John Doe",
            TrainerId = 3
        };

        // Act
        var result = _authController.AuthorizePersonalTrainer(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        
        var token = result as OkObjectResult;
        Assert.IsNotNull(token);
        Assert.IsInstanceOfType(token.Value, typeof(string));
    }
    
    [TestMethod]
    public void CreatePersonalTrainerToken_returns_400badrequestresult_on_malformed_request()
    {
        // Arrange
        PersonalTrainerDto dto = new PersonalTrainerDto()
        {
            TrainerId = 3
        };

        // Act
        var result = _authController.AuthorizePersonalTrainer(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(BadRequestObjectResult));
    }
    
    [TestMethod]
    public void CreatePersonalTrainerToken_returns_401unauthorizedresult_on_token_creation_failure()
    {
        _authController = new AuthController(_tokenProviderMock.Object, _logger.Object);
        _tokenProviderMock.Setup(provider => provider.CreatePersonalTrainerToken(It.IsAny<PersonalTrainerDto>()))
            .Returns(string.Empty);
        
        // Arrange
        PersonalTrainerDto dto = new PersonalTrainerDto()
        {
            Name = "John Doe",
            TrainerId = 3
        };

        // Act
        var result = _authController.AuthorizePersonalTrainer(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
        
    }
    
    [TestMethod]
    public void CreateAdminToken_returns_200OKObjectResult_and_token_on_valid_adminDTO()
    {
        // Arrange
        AdminDto dto = new AdminDto()
        {
            AdminId = 1,
            Username = "Marty mclfly"
        };

        // Act
        var result = _authController.AuthorizeAdmin(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(OkObjectResult));
        
        var token = result as OkObjectResult;
        Assert.IsNotNull(token);
        Assert.IsInstanceOfType(token.Value, typeof(string));
    }
    
    [TestMethod]
    public void CreateAdminToken_returns_400badrequestresult_on_malformed_request()
    {
        // Arrange
        AdminDto dto = new AdminDto()
        {
            AdminId = 1,
        };

        // Act
        var result = _authController.AuthorizeAdmin(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(BadRequestObjectResult));
    }
    
    [TestMethod]
    public void CreateAdminToken_returns_401unauthorizedresult_on_token_creation_failure()
    {
        // Arrange
        _authController = new AuthController(_tokenProviderMock.Object, _logger.Object);
        _tokenProviderMock.Setup(provider => provider.CreateAdminToken(It.IsAny<AdminDto>()))
            .Returns(string.Empty);
        AdminDto dto = new AdminDto()
        {
            AdminId = 1,
            Username = "Marty mclfly"
        };

        // Act
        var result = _authController.AuthorizeAdmin(dto);
        
        // Assert
        Assert.IsNotNull(result);
        Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
    }
}
