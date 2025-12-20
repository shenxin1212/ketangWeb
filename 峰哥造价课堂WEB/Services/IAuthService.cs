namespace 峰哥造价课堂WEB.Services
{
    public interface IAuthService
    {
        string GetCurrentUserRole();
        bool HasPermission(string requiredRole);
        string GetCurrentUsername();
        int GetCurrentUserId();
        string GetCurrentUserNickname();
        Task<bool> HasPermissionAsync(string permKey);
    }
}