using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Services;

namespace 峰哥造价课堂WEB.Controllers
{
    public class WeChatAuthController : Controller
    {
        private readonly IWeChatAuthService _weChatAuthService;
        private readonly ApplicationDbContext _context;

        public WeChatAuthController(IWeChatAuthService weChatAuthService, ApplicationDbContext context)
        {
            _weChatAuthService = weChatAuthService;
            _context = context;
        }

        [HttpGet]
        public IActionResult Login()
        {
            // 重定向到微信OAuth页面或显示二维码
            return View();
        }

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
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("OpenId", user.OpenId),
                    new Claim("AuthToken", authToken),
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Nickname", user.Nickname)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity));

                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                return RedirectToAction("Login", new { error = $"登录失败: {ex.Message}" });
            }
        }

        [HttpPost]
        public async Task<IActionResult> TokenLogin(string authToken)
        {
            // 用于其他系统传递token直接登录
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.AuthToken == authToken &&
                                         u.TokenExpiry > DateTime.Now &&
                                         u.Status == 1);

            if (user != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("OpenId", user.OpenId),
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Nickname", user.Nickname)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity));

                return Json(new { success = true, message = "登录成功" });
            }

            return Json(new { success = false, message = "Token无效或已过期" });
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        // 简化版微信登录 - 用于测试
        [HttpPost]
        public async Task<IActionResult> SimulateWeChatLogin(string openId, string nickname, string avatar = "")
        {
            try
            {
                var user = await _weChatAuthService.GetUserByOpenIdAsync(openId);
                if (user == null)
                {
                    // 创建新用户
                    user = await _weChatAuthService.CreateOrUpdateUserAsync(
                        openId,
                        $"unionid_{openId}",
                        nickname,
                        avatar);
                }

                var authToken = await _weChatAuthService.GenerateAuthTokenAsync(user);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("OpenId", user.OpenId),
                    new Claim("AuthToken", authToken),
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Nickname", user.Nickname)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity));

                return Json(new { success = true, message = "微信登录成功", user = new { user.UserName, user.Nickname, user.Role } });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = $"登录失败: {ex.Message}" });
            }
        }
    }
}