using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using Microsoft.AspNetCore.Authorization;
using 峰哥造价课堂WEB.Services;

namespace 峰哥造价课堂WEB.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService; // 添加此字段

        public AccountController(ApplicationDbContext context, IConfiguration configuration, IAuthService authService)
        {
            _context = context;
            _configuration = configuration;
            _authService = authService; 
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
            // 重定向到微信授权控制器
            return RedirectToAction("Login", "WeChatAuth");
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> CompleteProfile()
        {
            var userId = _authService.GetCurrentUserId();
            var user = await _context.Users.FindAsync(userId);

            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // 如果信息已完善，直接跳转到首页
            if (!string.IsNullOrEmpty(user.UserName) && !string.IsNullOrEmpty(user.Role) && user.IsActive)
            {
                return RedirectToAction("Index", "Home");
            }

            return View(user);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CompleteProfile(User model, string password)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users.FindAsync(model.Id);
            if (user == null)
            {
                return NotFound();
            }

            // 更新需要单独设置的字段
            user.UserName = model.UserName;
            user.Role = model.Role;
            user.IsActive = true; // 完善信息后激活账号

            // 如果提供了密码，则设置密码
            if (!string.IsNullOrEmpty(password))
            {
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);
            }

            user.UpdateTime = DateTime.Now;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            // 更新当前登录的Claims
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

            return RedirectToAction("Index", "Home");
        }
    }
}