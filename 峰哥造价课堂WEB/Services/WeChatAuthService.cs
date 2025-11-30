using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Services
{
    public interface IWeChatAuthService
    {
        Task<User?> AuthenticateAsync(string code);
        Task<User?> GetUserByOpenIdAsync(string openId);
        Task<User> CreateOrUpdateUserAsync(string openId, string unionId, string nickname, string avatar);
        Task<string> GenerateAuthTokenAsync(User user);
    }

    public class WeChatAuthService : IWeChatAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public WeChatAuthService(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<User?> AuthenticateAsync(string code)
        {
            // 这里实现微信OAuth2.0认证流程
            // 1. 使用code获取access_token和openid
            // 2. 使用access_token获取用户信息
            // 3. 创建或更新用户记录

            // 模拟实现 - 实际需要调用微信API
            var openId = await GetOpenIdFromWeChat(code);
            if (string.IsNullOrEmpty(openId))
                return null;

            var user = await GetUserByOpenIdAsync(openId);
            if (user == null)
            {
                // 如果用户不存在，创建新用户
                user = await CreateOrUpdateUserAsync(openId, $"unionid_{openId}", "微信用户", "");
            }

            return user;
        }

        public async Task<User?> GetUserByOpenIdAsync(string openId)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.OpenId == openId && u.Status == 1);
        }

        public async Task<User> CreateOrUpdateUserAsync(string openId, string unionId, string nickname, string avatar)
        {
            var user = await GetUserByOpenIdAsync(openId);

            if (user == null)
            {
                // 创建新用户
                user = new User
                {
                    OpenId = openId,
                    UnionId = unionId,
                    Nickname = nickname,
                    Avatar = avatar,
                    UserName = $"wx_{openId.Substring(0, 8)}", // 生成唯一用户名
                    Role = "User", // 默认角色
                    Status = 1,
                    IsActive = true,
                    CreateTime = DateTime.Now,
                    UpdateTime = DateTime.Now
                };
                await _context.Users.AddAsync(user);
            }
            else
            {
                // 更新现有用户信息
                user.Nickname = nickname;
                user.Avatar = avatar;
                user.UnionId = unionId;
                user.UpdateTime = DateTime.Now;
                _context.Users.Update(user);
            }

            await _context.SaveChangesAsync();
            return user;
        }

        public async Task<string> GenerateAuthTokenAsync(User user)
        {
            var token = Guid.NewGuid().ToString() + DateTime.Now.Ticks;
            user.AuthToken = BCrypt.Net.BCrypt.HashPassword(token);
            user.TokenExpiry = DateTime.Now.AddDays(7);
            user.UpdateTime = DateTime.Now;

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return token;
        }

        private async Task<string> GetOpenIdFromWeChat(string code)
        {
            // 模拟微信API调用
            await Task.Delay(100); // 模拟网络延迟

            // 实际实现需要调用微信API：
            // var wechatConfig = _configuration.GetSection("WeChat");
            // var appId = wechatConfig["AppId"];
            // var appSecret = wechatConfig["AppSecret"];
            // 然后调用微信API获取openid

            // 这里返回模拟的openid
            return $"wx_openid_{code}_{DateTime.Now.Ticks}";
        }
    }
}