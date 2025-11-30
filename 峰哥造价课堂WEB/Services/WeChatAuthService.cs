using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;

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
        private readonly HttpClient _httpClient;

        public WeChatAuthService(
            ApplicationDbContext context,
            IConfiguration configuration,
            HttpClient httpClient)
        {
            _context = context;
            _configuration = configuration;
            _httpClient = httpClient;
        }

        /// <summary>
        /// 微信认证核心方法
        /// </summary>
        public async Task<User?> AuthenticateAsync(string code)
        {
            try
            {
                // 1. 使用code获取access_token和openid
                var wechatConfig = _configuration.GetSection("WeChat");
                var appId = wechatConfig["AppId"];
                var appSecret = wechatConfig["AppSecret"];

                var tokenResponse = await _httpClient.GetFromJsonAsync<WeChatTokenResponse>(
                    $"https://api.weixin.qq.com/sns/oauth2/access_token?appid={appId}&secret={appSecret}&code={code}&grant_type=authorization_code");

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.openid))
                {
                    return null;
                }

                // 2. 使用access_token获取用户信息
                var userInfo = await _httpClient.GetFromJsonAsync<WeChatUserInfo>(
                    $"https://api.weixin.qq.com/sns/userinfo?access_token={tokenResponse.access_token}&openid={tokenResponse.openid}&lang=zh_CN");

                if (userInfo == null)
                {
                    return null;
                }

                // 3. 创建或更新用户
                return await CreateOrUpdateUserAsync(
                    userInfo.openid,
                    userInfo.unionid ?? $"union_{userInfo.openid}",
                    userInfo.nickname,
                    userInfo.headimgurl);
            }
            catch (Exception ex)
            {
                // 记录错误日志
                Console.WriteLine($"微信认证失败: {ex.Message}");
                return null;
            }
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
                    UserName = $"wx_{GenerateRandomString(8)}", // 生成唯一用户名
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

        /// <summary>
        /// 生成随机字符串
        /// </summary>
        private string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        // 微信接口响应模型
        private class WeChatTokenResponse
        {
            public string access_token { get; set; } = string.Empty;
            public int expires_in { get; set; }
            public string refresh_token { get; set; } = string.Empty;
            public string openid { get; set; } = string.Empty;
            public string scope { get; set; } = string.Empty;
            public string unionid { get; set; } = string.Empty;
        }

        private class WeChatUserInfo
        {
            public string openid { get; set; } = string.Empty;
            public string nickname { get; set; } = string.Empty;
            public int sex { get; set; }
            public string province { get; set; } = string.Empty;
            public string city { get; set; } = string.Empty;
            public string country { get; set; } = string.Empty;
            public string headimgurl { get; set; } = string.Empty;
            public string[] privilege { get; set; } = Array.Empty<string>();
            public string unionid { get; set; } = string.Empty;
        }
    }
}