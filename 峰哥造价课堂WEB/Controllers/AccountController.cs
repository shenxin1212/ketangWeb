using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public AccountController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration; 
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            // 查找用户 - 现在通过UserName字段查找
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.UserName == username && u.IsActive && u.Status == 1);

            if (user != null)
            {
                // 检查密码（如果有设置密码）
                if (!string.IsNullOrEmpty(user.PasswordHash) &&
                    BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
                {
                    await SignInUser(user);
                    return RedirectToAction("Index", "Home");
                }
                // 如果没有设置密码，允许直接登录（适用于微信用户）
                else if (string.IsNullOrEmpty(user.PasswordHash))
                {
                    await SignInUser(user);
                    return RedirectToAction("Index", "Home");
                }
            }

            ViewBag.Error = "用户名或密码错误";
            return View();
        }

        private async Task SignInUser(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("UserId", user.Id.ToString()),
                new Claim("Nickname", user.Nickname)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        // 微信登录入口
        [HttpGet]
        public IActionResult WeChatLogin(string returnUrl = "/")
        {
            // 从配置文件读取微信参数
            var wechatConfig = _configuration.GetSection("WeChat");
            var appId = wechatConfig["AppId"];
            var redirectUri = $"{wechatConfig["RedirectUri"]}/WeChatAuth/Callback"; // 回调地址需与微信开放平台配置一致

            // 对回调地址进行 URL 编码
            var encodedRedirectUri = System.Web.HttpUtility.UrlEncode(redirectUri);

            // 构造微信扫码登录链接（PC端用 snsapi_login）
            var authUrl = $"https://open.weixin.qq.com/connect/qrconnect" +
                          $"?appid={appId}" +
                          $"&redirect_uri={encodedRedirectUri}" +
                          $"&response_type=code" +
                          $"&scope=snsapi_login" +
                          $"&state={returnUrl}#wechat_redirect";

            // 重定向到微信扫码页面
            return Redirect(authUrl);
        }
    }
}