using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using 峰哥造价课堂WEB.Services;
using Microsoft.AspNetCore.Authorization;

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
                    return RedirectToAction("CompleteInfo");
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
        [AcceptVerbs("GET", "POST")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckUserNameUnique(string userName)
        {
            // 空值防护
            if (string.IsNullOrWhiteSpace(userName))
            {
                return Json("用户名不能为空");
            }

            // 核心：仅检查用户名是否存在（全局唯一，不涉及 OpenId）
            var exists = await _context.Users
                .AnyAsync(u => u.UserName == userName);

            // true=可用，false=已占用
            return Json(!exists);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult CompleteInfo(string returnUrl = "/")
        {
            // 从查询参数获取 OpenId（登录时传递的）
            var openId = HttpContext.Request.Query["openId"].ToString();

            // 初始化 ViewModel，绑定 OpenId（用于后续提交）
            var model = new UserInfoViewModel
            {
                OpenId = openId,
                ReturnUrl = returnUrl
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompleteInfo(UserInfoViewModel model)
        {
            // 1. 先验证模型（包含用户名远程验证）
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // 补充后端校验：检查用户名是否已存在
            var userNameExists = await _context.Users.AnyAsync(u => u.UserName == model.UserName);
            if (userNameExists)
            {
                ModelState.AddModelError("UserName", "用户名已被占用，请更换");
                return View(model);
            }

            // 2. 用 OpenId 匹配当前用户（登录核心逻辑，保留 OpenId 作用）
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.OpenId == model.OpenId);

            if (user == null)
            {
                ModelState.AddModelError("", "用户不存在，请重新登录");
                return View(model);
            }

            // 3. 更新用户信息（用户名已通过全局唯一验证）
            user.UserName = model.UserName;
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);
            user.UpdateTime = DateTime.Now;

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            // 4. 重新登录（用 OpenId/用户名）
            await SignInUser(user);

            // 5. 跳转指定页面
            return LocalRedirect(model.ReturnUrl ?? "/");
        }
    }
}