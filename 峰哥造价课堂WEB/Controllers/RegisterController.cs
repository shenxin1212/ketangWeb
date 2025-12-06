using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using System.Security.Claims;

namespace 峰哥造价课堂WEB.Controllers
{
    public class RegisterController : Controller
    {
        private readonly ApplicationDbContext _context;

        public RegisterController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Index(string returnUrl = "/")
        {
            // 修正 ViewBagbag 拼写错误
            ViewBag.ReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
            // 检查是否已微信登录
            ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // 增加防跨站攻击
        public async Task<IActionResult> Index(string username, string password, string confirmPassword, string returnUrl = "/")
        {
            // 安全验证 returnUrl
            var safeReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";

            // 基础验证
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                ViewBag.Error = "用户名和密码不能为空";
                ViewBag.ReturnUrl = safeReturnUrl;
                ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;
                return View();
            }

            if (password != confirmPassword)
            {
                ViewBag.Error = "两次输入的密码不一致";
                ViewBag.ReturnUrl = safeReturnUrl;
                ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;
                return View();
            }

            if (password.Length < 6)
            {
                ViewBag.Error = "密码长度不能少于6位";
                ViewBag.ReturnUrl = safeReturnUrl;
                ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;
                return View();
            }

            try
            {
                // 检查用户名是否存在
                if (await _context.Users.AnyAsync(u => u.UserName == username))
                {
                    ViewBag.Error = "用户名已存在";
                    ViewBag.ReturnUrl = safeReturnUrl;
                    ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;
                    return View();
                }

                // 检查是否已微信登录（关联账号）
                if (User.Identity?.IsAuthenticated ?? false)
                {
                    var userIdClaim = User.FindFirstValue("UserId");
                    if (int.TryParse(userIdClaim, out int userId))
                    {
                        var user = await _context.Users.FindAsync(userId);

                        if (user != null)
                        {
                            user.UserName = username;
                            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);
                            user.UpdateTime = DateTime.Now;
                            _context.Users.Update(user);
                            await _context.SaveChangesAsync();

                            // 更新登录凭证
                            var claims = new List<Claim>
                            {
                                new Claim(ClaimTypes.Name, user.UserName),
                                new Claim(ClaimTypes.Role, user.Role),
                                new Claim("UserId", user.Id.ToString()),
                                new Claim("Nickname", user.Nickname ?? user.UserName)
                            };

                            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                new ClaimsPrincipal(claimsIdentity));

                            return Redirect(safeReturnUrl);
                        }
                    }

                    ViewBag.Error = "微信用户信息获取失败";
                }
                else
                {
                    // 新用户注册
                    var user = new User
                    {
                        UserName = username,
                        PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                        Nickname = username,
                        Role = "User",
                        Status = 1,
                        IsActive = true,
                        CreateTime = DateTime.Now,
                        UpdateTime = DateTime.Now
                    };

                    await _context.Users.AddAsync(user);
                    await _context.SaveChangesAsync();

                    // 自动登录
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

                    return Redirect(safeReturnUrl);
                }
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"注册失败: {ex.Message}";
                ViewBag.ReturnUrl = safeReturnUrl;
                ViewBag.IsWeChatUser = User.Identity?.IsAuthenticated ?? false;
            }

            return View();
        }
    }
}