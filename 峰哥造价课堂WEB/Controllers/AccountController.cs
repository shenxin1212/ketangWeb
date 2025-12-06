using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using 峰哥造价课堂WEB.Services;

namespace 峰哥造价课堂WEB.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService;

        public AccountController(ApplicationDbContext context, IConfiguration configuration, IAuthService authService)
        {
            _context = context;
            _configuration = configuration;
            _authService = authService; // 关键：注入IAuthService
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            // 查找用户 - 通过UserName字段查找
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.UserName == username && u.IsActive && u.Status == 1);

            if (user != null)
            {
                // 检查密码（如果有设置密码）
                if (!string.IsNullOrEmpty(user.PasswordHash) &&
                    BCrypt.Net.BCrypt.Verify(password, user.PasswordHash)) // 修正：简化命名空间调用
                {
                    await SignInUser(user);
                    return RedirectToAction("Index", "Home");
                }
                // 如果没有设置密码，强制跳转完善信息（原逻辑直接登录，此处修正为跳转）
                else if (string.IsNullOrEmpty(user.PasswordHash))
                {
                    // 记录用户ID用于完善信息页面验证
                    TempData["TempUserId"] = user.Id;
                    return RedirectToAction("CompleteRegistration");
                }
            }

            ViewBag.Error = "用户名或密码错误";
            return View();
        }

        private async Task SignInUser(User user)
        {
            // 修正：使用User类的安全属性避免空引用
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.SafeUserName),  // 替代user.UserName
                new Claim(ClaimTypes.Role, user.SafeRole),      // 替代user.Role
                new Claim("UserId", user.Id.ToString()),
                new Claim("Nickname", user.SafeNickname)        // 替代user.Nickname
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
            var wechatConfig = _configuration.GetSection("WeChat");
            var appId = wechatConfig["AppId"];
            var redirectUri = $"{wechatConfig["RedirectUri"]}/WeChatAuth/Callback";

            var encodedRedirectUri = System.Web.HttpUtility.UrlEncode(redirectUri);

            var authUrl = $"https://open.weixin.qq.com/connect/qrconnect" +
                          $"?appid={appId}" +
                          $"&redirect_uri={encodedRedirectUri}" +
                          $"&response_type=code" +
                          $"&scope=snsapi_login" +
                          $"&state={returnUrl}#wechat_redirect";

            return Redirect(authUrl);
        }

        [HttpGet]
        public IActionResult CompleteInfo(string returnUrl = "/")
        {
            // 从查询参数或登录中获取 openId（如果需要）
            var openId = HttpContext.Request.Query["openId"].ToString();

            // 传递 returnUrl 和 openId 到视图，用于表单提交
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["OpenId"] = openId;

            // 返回信息完善表单视图
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CompleteInfo(UserInfoViewModel model, string returnUrl = "/")
        {
            if (ModelState.IsValid)
            {
                var userId = _authService.GetCurrentUserId();
                var user = await _context.Users.FindAsync(userId);

                if (user != null)
                {
                    // 更新用户名和密码
                    user.UserName = model.UserName;
                    user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);
                    user.UpdateTime = DateTime.Now;

                    _context.Users.Update(user);
                    await _context.SaveChangesAsync();

                    // 重新登录以更新身份信息
                    await SignInUser(user);

                    return RedirectToAction("Index", "Home");
                }
            }

            return View(model);
        }
    }
}