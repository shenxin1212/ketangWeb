using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using System.Text.Json.Serialization;
using System.Data;

namespace 峰哥造价课堂WEB.Controllers
{
    public class WeChatAuthController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public WeChatAuthController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // 定义微信token响应模型
        private class WeChatTokenResponse
        {
            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; } = string.Empty;

            [JsonPropertyName("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonPropertyName("refresh_token")]
            public string RefreshToken { get; set; } = string.Empty;

            [JsonPropertyName("openid")]
            public string OpenId { get; set; } = string.Empty;

            [JsonPropertyName("scope")]
            public string Scope { get; set; } = string.Empty;

            [JsonPropertyName("unionid")]
            public string unionid { get; set; } = string.Empty;

            [JsonPropertyName("errcode")]
            public int? ErrCode { get; set; }

            [JsonPropertyName("errmsg")]
            public string ErrMsg { get; set; } = string.Empty;
        }

        public async Task<IActionResult> Callback(string code, string state)
        {
            try
            {
                // 1. 获取微信AccessToken和OpenId
                var wechatConfig = _configuration.GetSection("WeChat");
                var appId = wechatConfig["AppId"];
                var appSecret = wechatConfig["AppSecret"];

                using (var httpClient = new HttpClient())
                {
                    var tokenUrl = $"https://api.weixin.qq.com/sns/oauth2/access_token?appid={appId}&secret={appSecret}&code={code}&grant_type=authorization_code";
                    var tokenResponse = await httpClient.GetStringAsync(tokenUrl);
                    var tokenData = JsonSerializer.Deserialize<WeChatTokenResponse>(tokenResponse);

                    // 检查是否有错误码
                    if (tokenData.ErrCode.HasValue && tokenData.ErrCode != 0)
                    {
                        return RedirectToAction("Login", "Account", new { error = $"微信授权失败: {tokenData.ErrMsg}" });
                    }

                    // 2. 获取用户信息
                    var accessToken = tokenData.AccessToken;
                    var openId = tokenData.OpenId;
                    var userInfoUrl = $"https://api.weixin.qq.com/sns/userinfo?access_token={accessToken}&openid={openId}&lang=zh_CN";
                    var userInfoResponse = await httpClient.GetStringAsync(userInfoUrl);
                    var userInfo = JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoResponse);

                    // 3. 查找或创建用户
                    var user = await _context.Users.FirstOrDefaultAsync(u => u.OpenId == openId);

                    if (user == null)
                    {
                        // 创建新用户
                        user = new User
                        {
                            OpenId = openId,
                            UnionId = userInfo.TryGetValue("unionid", out var unionId) ? unionId.ToString() : string.Empty,
                            Nickname = userInfo.TryGetValue("nickname", out var nickname) ? nickname.ToString() : string.Empty,
                            Avatar = userInfo.TryGetValue("headimgurl", out var avatar) ? avatar.ToString() : string.Empty,
                            Role = "User",
                            Status = 1,
                            IsActive = true,
                            CreateTime = DateTime.Now,
                            UpdateTime = DateTime.Now,
                            UserName = $"wx_{openId.Substring(0, 8)}", // 生成用户名
                            PasswordHash = string.Empty
                        };
                        _context.Users.Add(user);
                        await _context.SaveChangesAsync();
                    }
                    else
                    {
                        // 更新现有用户信息
                        user.Nickname = userInfo.TryGetValue("nickname", out var nickname) ? nickname.ToString() : user.Nickname;
                        user.Avatar = userInfo.TryGetValue("headimgurl", out var avatar) ? avatar.ToString() : user.Avatar;
                        user.UnionId = userInfo.TryGetValue("unionid", out var unionId) ? unionId.ToString() : user.UnionId;
                        user.Role = "User";
                        user.UpdateTime = DateTime.Now;
                        _context.Users.Update(user);
                        await _context.SaveChangesAsync();
                    }

                    // 执行登录操作
                    await SignInUser(user);

                    // 根据state参数决定跳转地址
                    if (!string.IsNullOrEmpty(state) && Url.IsLocalUrl(state))
                    {
                        return Redirect(state);
                    }

                    if (string.IsNullOrEmpty(user.UserName) || string.IsNullOrEmpty(user.PasswordHash))
                    {
                        // 用户名或密码为空，跳转到完善信息页面
                        return RedirectToAction("CompleteInfo", "Account", new { OpenId = user.OpenId });
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }

                }
            }
            catch (Exception ex)
            {
                // 输出异常到控制台
                Console.WriteLine($"微信登录异常: {ex}");
                return RedirectToAction("Login", "Account", new { error = $"微信登录失败: {ex.Message}" });
            }
        }

        private async Task SignInUser(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.SafeUserName),
                new Claim(ClaimTypes.Role, user.SafeRole),
                new Claim("UserId", user.Id.ToString()),
                new Claim("Nickname", user.SafeNickname),
                new Claim("OpenId", user.SafeOpenId)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties { IsPersistent = true } // 持久化登录状态
            );
        }
    }
}