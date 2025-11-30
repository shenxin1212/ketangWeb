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
        public async Task<IActionResult> Callback(string code, string state)
        {
            // 验证state防止CSRF攻击
            var sessionState = HttpContext.Session.GetString("WeChatAuthState");
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || state != sessionState)
            {
                TempData["ErrorMessage"] = "授权验证失败";
                return RedirectToAction("Login", "Account");
            }

            try
            {
                // 通过code获取用户信息并认证
                var user = await _weChatAuthService.AuthenticateAsync(code);
                if (user == null)
                {
                    TempData["ErrorMessage"] = "用户信息获取失败";
                    return RedirectToAction("Login", "Account");
                }

                // 生成认证token
                var authToken = await _weChatAuthService.GenerateAuthTokenAsync(user);

                // 创建用户身份标识
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("OpenId", user.OpenId),
                    new Claim("AuthToken", authToken),
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Nickname", user.Nickname)
                };

                // 登录用户
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                    });

                // 登录成功跳转到首页
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"登录失败: {ex.Message}";
                return RedirectToAction("Login", "Account");
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