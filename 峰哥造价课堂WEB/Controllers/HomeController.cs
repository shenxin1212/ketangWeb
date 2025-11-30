using Microsoft.AspNetCore.Mvc;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using 峰哥造价课堂WEB.Services;

namespace VideoManagementSystem.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IAuthService _authService;

        public HomeController(ApplicationDbContext context, IAuthService authService)
        {
            _context = context;
            _authService = authService;
        }

        public IActionResult Index()
        {
            try
            {
                // 1. 获取所有允许游客下载的文件（无需登录）
                var publicDownloads = _context.DownloadFiles
                    .Where(f => f.RequiredRole == "Guest") // 只筛选 Guest 可访问的文件
                    .OrderByDescending(f => f.UploadDate)
                    .Take(1) // 只显示1个应用程序（可根据需求调整数量）
                    .ToList();

                // 2. 其他原有数据（视频、登录用户可见的文件）
                var currentUserRole = _authService.GetCurrentUserRole();
                var accessibleRoles = GetAccessibleRoles(currentUserRole);

                var videos = _context.Videos
                    .Where(v => v.IsPublic || accessibleRoles.Contains(v.RequiredRole))
                    .Take(6)
                    .ToList();

                var memberFiles = _context.DownloadFiles
                    .Where(f => accessibleRoles.Contains(f.RequiredRole) && f.RequiredRole != "Guest")
                    .Take(3)
                    .ToList();

                // 3. 传递到视图
                ViewBag.PublicDownloads = publicDownloads; // 游客可见的下载文件
                ViewBag.Videos = videos;
                ViewBag.Files = memberFiles; // 登录用户可见的其他文件
                ViewBag.UserRole = currentUserRole;
                ViewBag.Username = _authService.GetCurrentUserNickname();
                ViewBag.UserId = _authService.GetCurrentUserId();

                return View();
            }
            catch (Exception ex)
            {
                // 错误处理
                ViewBag.PublicDownloads = new List<DownloadFile>();
                ViewBag.Videos = new List<Video>();
                ViewBag.Files = new List<DownloadFile>();
                ViewBag.UserRole = "Guest";
                ViewBag.Username = "游客";
                ViewBag.UserId = 0;
                return View();
            }
        }

        // 辅助方法：获取登录用户可访问的角色（复用逻辑）
        private string[] GetAccessibleRoles(string userRole)
        {
            var roleHierarchy = new Dictionary<string, int>
            {
                ["Admin"] = 3,
                ["User"] = 2,
                ["Guest"] = 1
            };
            var userRoleValue = roleHierarchy.ContainsKey(userRole) ? roleHierarchy[userRole] : 0;
            return roleHierarchy
                .Where(r => r.Value <= userRoleValue)
                .Select(r => r.Key)
                .ToArray();
        }


        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult Test()
        {
            return View();
        }

    }
}