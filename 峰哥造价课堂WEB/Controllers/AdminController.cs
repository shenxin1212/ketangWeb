using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace VideoManagementSystem.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AdminController(ApplicationDbContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            var stats = new
            {
                TotalUsers = _context.Users.Count(),
                TotalVideos = _context.Videos.Count(),
                TotalDownloads = _context.DownloadFiles.Count(),
                TotalDownloadCount = _context.DownloadFiles.Sum(d => d.DownloadCount)
            };

            ViewBag.Stats = stats;
            return View();
        }

        public async Task<IActionResult> Users()
        {
            var users = await _context.Users
                .OrderBy(u => u.Id)
                .ToListAsync();
            return View(users);
        }

        public async Task<IActionResult> Videos()
        {
            var videos = await _context.Videos
                .OrderByDescending(v => v.UploadDate)
                .ToListAsync();
            return View(videos);
        }

        public async Task<IActionResult> DownloadFiles()
        {
            var files = await _context.DownloadFiles
                .OrderByDescending(f => f.UploadDate)
                .ToListAsync();
            return View(files);
        }

        [HttpPost]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null && user.UserName != "admin") // 防止删除管理员自己
            {
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction("Users");
        }

        [HttpPost]
        public async Task<IActionResult> ToggleUserStatus(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null && user.UserName != "admin")
            {
                user.IsActive = !user.IsActive;
                user.UpdateTime = DateTime.Now; // 更新修改时间
                await _context.SaveChangesAsync();
            }

            return RedirectToAction("Users");
        }

        // 新增：编辑用户信息
        [HttpGet]
        public async Task<IActionResult> EditUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(User user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _context.Users.FindAsync(user.Id);
                if (existingUser != null)
                {
                    // 只更新允许修改的字段
                    existingUser.UserName = user.UserName;
                    existingUser.Nickname = user.Nickname;
                    existingUser.Mobile = user.Mobile;
                    existingUser.Role = user.Role;
                    existingUser.IsActive = user.IsActive;
                    existingUser.UpdateTime = DateTime.Now;

                    _context.Users.Update(existingUser);
                    await _context.SaveChangesAsync();

                    return RedirectToAction("Users");
                }
            }
            return View(user);
        }

        // 新增：重置用户密码
        [HttpPost]
        public async Task<IActionResult> ResetPassword(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null && user.UserName != "admin")
            {
                // 重置为默认密码
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456");
                user.UpdateTime = DateTime.Now;
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = $"用户 {user.UserName} 的密码已重置为 123456";
            }

            return RedirectToAction("Users");
        }
    }
}