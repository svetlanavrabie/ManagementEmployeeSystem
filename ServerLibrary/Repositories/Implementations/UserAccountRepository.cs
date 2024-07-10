using BaseLibrary.Dtos;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;

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
            var userRole = await dbContext.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == appUser.Id);
            if (userRole is null)
            {
                return new LoginResponse(false, Messages.M07);
            }

            // Check system role
            var systemRoleName = await dbContext.SystemRoles.FirstOrDefaultAsync(sr => sr.Id == userRole.RoleId);
            if (systemRoleName is null)
            {
                return new LoginResponse(false, Messages.M09);
            }

            var jwtToken = GenerateToken(appUser, systemRoleName!.Name!);
            var refreshToken = GenerateRefreshToken();

            return new LoginResponse(true, Messages.M08, jwtToken, refreshToken);
        }

        private async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            return await dbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Email!.Equals(email!));
        }

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = dbContext.Add(model!);
            await dbContext.SaveChangesAsync();
            return (T)result.Entity;
        }
    }
}
