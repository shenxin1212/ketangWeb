using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Services;
using 峰哥造价课堂WEB.Models;
using Microsoft.AspNetCore.Authentication;
using System.Web;

namespace 峰哥造价课堂WEB.Controllers
{
    public class WeChatAuthController : Controller
    {
        private readonly IWeChatAuthService _weChatAuthService;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public WeChatAuthController(
            IWeChatAuthService weChatAuthService,
            ApplicationDbContext context,
            IConfiguration configuration)
        {
            _weChatAuthService = weChatAuthService;
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// 微信登录入口 - 生成微信授权链接
        /// </summary>
        [HttpGet]
        public IActionResult Login()
        {
            try
            {
                var appId = _configuration["WeChat:AppId"];
                var redirectUri = HttpUtility.UrlEncode($"{_configuration["WeChat:RedirectUri"]}/WeChatAuth/Callback");
                var scope = "snsapi_login"; // 网页授权类型
                var state = Guid.NewGuid().ToString("N"); // 随机状态值，用于防CSRF

                // 存储state到会话，用于回调验证
                HttpContext.Session.SetString("WeChatAuthState", state);

                // 构建微信授权链接
                var authUrl = $"https://open.weixin.qq.com/connect/qrconnect" +
                             $"?appid={appId}" +
                             $"&redirect_uri={redirectUri}" +
                             $"&response_type=code" +
                             $"&scope={scope}" +
                             $"&state={state}#wechat_redirect";

                return Redirect(authUrl);
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"登录准备失败: {ex.Message}";
                return RedirectToAction("Login", "Account");
            }
        }

        /// <summary>
        /// 微信授权回调处理
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Callback(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return RedirectToAction("Login", new { error = "授权失败" });
            }

            try
            {
                var user = await _weChatAuthService.AuthenticateAsync(code);
                if (user == null)
                {
                    return RedirectToAction("Login", new { error = "用户认证失败" });
                }

                // 生成认证token
                var authToken = await _weChatAuthService.GenerateAuthTokenAsync(user);

                // 创建Claims身份
                var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, string.IsNullOrEmpty(user.UserName) ? user.SafeNickname : user.UserName),
            new Claim(ClaimTypes.Role, string.IsNullOrEmpty(user.Role) ? "Pending" : user.Role),
            new Claim("OpenId", user.OpenId),
            new Claim("AuthToken", authToken),
            new Claim("UserId", user.Id.ToString()),
            new Claim("Nickname", user.Nickname)
        };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity));

                // 检查是否需要完善信息（UserName、Role、IsActive为空）
                if (string.IsNullOrEmpty(user.UserName) || string.IsNullOrEmpty(user.Role) || !user.IsActive)
                {
                    // 重定向到完善信息页面
                    return RedirectToAction("CompleteProfile", "Account");
                }

                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                return RedirectToAction("Login", new { error = $"登录失败: {ex.Message}" });
            }
        }

        /// <summary>
        /// 退出登录
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}