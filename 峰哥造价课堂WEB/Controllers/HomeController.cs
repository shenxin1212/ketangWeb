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
                var videos = _context.Videos
                    .Where(v => v.IsPublic || _authService.HasPermission(v.RequiredRole))
                    .Take(6)
                    .ToList();

                var files = _context.DownloadFiles
                    .Where(f => _authService.HasPermission(f.RequiredRole))
                    .Take(3)
                    .ToList();

                ViewBag.Videos = videos;
                ViewBag.Files = files;
                ViewBag.UserRole = _authService.GetCurrentUserRole();
                ViewBag.Username = _authService.GetCurrentUserNickname();
                ViewBag.UserId = _authService.GetCurrentUserId();

                return View();
            }
            catch (Exception ex)
            {
                // 如果出现错误，使用默认值
                ViewBag.Videos = new List<Video>();
                ViewBag.Files = new List<DownloadFile>();
                ViewBag.UserRole = "Guest";
                ViewBag.Username = "游客";
                ViewBag.UserId = 0;

                return View();
            }
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