using AuthAPI.Models;

namespace AuthAPI.Token;

public interface ITokenProvider
{
    string CreateMemberToken(MemberDto member);
    string CreatePersonalTrainerToken(PersonalTrainerDto trainer);
    string CreateAdminToken(AdminDto admin);
}