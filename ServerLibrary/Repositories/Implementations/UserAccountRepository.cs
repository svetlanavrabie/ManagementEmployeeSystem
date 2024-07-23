using BaseLibrary.Dtos;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext dbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null)
            {
                return new GeneralResponse(false, Messages.M02);
            }

            var checkUser = await FindUserByEmailAsync(user.Email!);

            if (checkUser != null)
            {
                return new GeneralResponse(false, Messages.M02);
            }

            var appUser = await AddToDatabase(new ApplicationUser()
            {
                FullName = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // Create admin
            var checkAdminRole = await dbContext.SystemRoles.FirstOrDefaultAsync(r => r.Name!.Equals(Constants.Admin));

            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole()
                {
                    Name = Constants.Admin
                });

                await AddToDatabase(new UserRole()
                {
                    RoleId = createAdminRole.Id,
                    UserId = appUser.Id
                });

                return new GeneralResponse(true, Messages.M04);
            }

            // Create user
            var checkUserRole = await dbContext.SystemRoles.FirstOrDefaultAsync(r => r.Name!.Equals(Constants.User));
            SystemRole response = new();

            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole()
                {
                    Name = Constants.User
                });

                await AddToDatabase(new UserRole()
                {
                    RoleId = response.Id,
                    UserId = appUser.Id
                });
            }
            else
            {
                await AddToDatabase(new UserRole()
                {
                    RoleId = checkUserRole.Id,
                    UserId = appUser.Id
                });
            }

            return new GeneralResponse(true, "Account Created!");
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null)
            {
                return new LoginResponse(false, Messages.M02);
            }

            var appUser = await FindUserByEmailAsync(user.Email!);
            if (appUser is null)
            {
                return new LoginResponse(false, Messages.M05);
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, appUser.Password))
            {
                return new LoginResponse(false, Messages.M06);
            }

            // Check user role
            var userRole = await FindUserRoleAsync(appUser.Id);
            if (userRole is null)
            {
                return new LoginResponse(false, Messages.M07);
            }

            // Check system role
            var systemRoleName = await FindRoleNameAsync(userRole.RoleId);
            if (systemRoleName is null)
            {
                return new LoginResponse(false, Messages.M07);
            }

            var jwtToken = GenerateToken(appUser, systemRoleName!.Name!);
            var refreshToken = GenerateRefreshToken();

            // Save refresh token to the database
            var findRefreshToken = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.UserId.Equals(appUser.Id));

            if (findRefreshToken is not null)
            {
                findRefreshToken.Token = refreshToken;
                await dbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDatabase(new RefreshTokenInfo()
                {
                    Token = refreshToken,
                    UserId = appUser.Id
                });
            }

            return new LoginResponse(true, Messages.M09, jwtToken, refreshToken);
        }

        private string GenerateToken(ApplicationUser appUser, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, appUser.Id.ToString()),
                new Claim(ClaimTypes.Name, appUser.FullName),
                new Claim(ClaimTypes.Email, appUser.Email),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }

        private async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            return await dbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Email!.Equals(email!));
        }

        private async Task<UserRole> FindUserRoleAsync(int userId)
        {
            return await dbContext.UserRoles.FirstOrDefaultAsync(u => u.UserId == userId);
        }

        private async Task<SystemRole> FindRoleNameAsync(int roleId)
        {
            return await dbContext.SystemRoles.FirstOrDefaultAsync(u => u.Id == roleId);
        }

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = dbContext.Add(model!);
            await dbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null)
            {
                return new LoginResponse(false, Messages.M02);
            }

            var findToken = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.Token.Equals(token.Token));

            if (findToken is null)
            {
                return new LoginResponse(false, Messages.M10);
            }

            // get user details
            var user = await dbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Id == findToken.UserId);
            if (user is null)
            {
                return new LoginResponse(false, Messages.M11);
            }

            var userRole = await FindUserRoleAsync(user.Id);
            var roleName = await FindRoleNameAsync(userRole.RoleId);
            var jwtToken = GenerateToken(user, roleName.Name);
            var refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.UserId == user.Id);
            if (updateRefreshToken is null)
            {
                return new LoginResponse(false, Messages.M12);
            }

            updateRefreshToken.Token = refreshToken;
            await dbContext.SaveChangesAsync();

            return new LoginResponse(true, Messages.M13, jwtToken, refreshToken);
        }
    }
}
