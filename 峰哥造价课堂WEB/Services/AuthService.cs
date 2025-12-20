using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Services
{
    public class AuthService : IAuthService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ApplicationDbContext _context;

        public AuthService(IHttpContextAccessor httpContextAccessor, ApplicationDbContext context)
        {
            _httpContextAccessor = httpContextAccessor;
            _context = context;
        }

        public string GetCurrentUserRole()
        {
            return _httpContextAccessor.HttpContext?.User?.FindFirst(ClaimTypes.Role)?.Value ?? "Guest";
        }

        public string GetCurrentUsername()
        {
            return _httpContextAccessor.HttpContext?.User?.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        }

        public int GetCurrentUserId()
        {
            var userIdClaim = _httpContextAccessor.HttpContext?.User?.FindFirst("UserId")?.Value;
            return int.TryParse(userIdClaim, out int userId) ? userId : 0;
        }

        public string GetCurrentUserNickname()
        {
            return _httpContextAccessor.HttpContext?.User?.FindFirst("Nickname")?.Value ?? GetCurrentUsername();
        }

        public bool HasPermission(string requiredRole)
        {
            var currentRole = GetCurrentUserRole();

            var roleHierarchy = new Dictionary<string, int>
            {
                ["Admin"] = 3,
                ["User"] = 2,
                ["Guest"] = 1
            };

            if (roleHierarchy.ContainsKey(currentRole) && roleHierarchy.ContainsKey(requiredRole))
            {
                return roleHierarchy[currentRole] >= roleHierarchy[requiredRole];
            }

            return false;
        }

        // 获取当前用户完整信息
        public async Task<User?> GetCurrentUserAsync()
        {
            var userId = GetCurrentUserId();
            if (userId > 0)
            {
                return await _context.Users.FindAsync(userId);
            }
            return null;
        }

        public async Task<bool> HasPermissionAsync(string permKey)
        {
            var userId = GetCurrentUserId();
            if (userId <= 0) return false;

            var user = await _context.Users
                .Include(u => u.UserPermissions)
                .ThenInclude(up => up.Permission)
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null) return false;

            // 管理员拥有所有权限
            if (user.IsAdmin) return true;

            return user.UserPermissions.Any(up => up.Permission.PermKey == permKey);
        }
    }
}