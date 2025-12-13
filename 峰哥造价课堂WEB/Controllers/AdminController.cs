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
        // 会员管理页面
        public async Task<IActionResult> Members(string statusFilter = "all", string nickname = "")
        {
            // 查询用户及权限数据（对应原VB的SQL逻辑）
            var query = from u in _context.Users
                        join p in _context.UserPermissions on u.Id equals p.UserId into up
                        from perm in up.DefaultIfEmpty()
                        group perm by new { u.Id, u.Nickname, u.CreateTime, u.Status } into g
                        select new MemberViewModel
                        {
                            Id = g.Key.Id,
                            Nickname = g.Key.Nickname ?? "未知用户",
                            CreateTime = g.Key.CreateTime ?? DateTime.MinValue,
                            Status = g.Key.Status == 0 ? "试用用户" : "试用已结束",
                            // 提取成本测算和助手的到期时间
                            CesuanExpiry = g.Where(p => p.PermId == 1).Max(p => p.GrantTime),
                            ZhushouExpiry = g.Where(p => p.PermId == 2).Max(p => p.GrantTime)
                        };

            // 计算综合状态（对应原VB的状态判断逻辑）
            var members = await query.ToListAsync();
            foreach (var m in members)
            {
                var currentTime = DateTime.Now;
                var createTime = m.CreateTime;

                if (m.CesuanExpiry.HasValue && m.ZhushouExpiry.HasValue &&
                    m.CesuanExpiry < createTime && m.ZhushouExpiry < createTime)
                {
                    m.ShowStatus = "新用户";
                }
                else if ((m.CesuanExpiry.HasValue && m.CesuanExpiry > createTime && m.CesuanExpiry > currentTime) ||
                         (m.ZhushouExpiry.HasValue && m.ZhushouExpiry > createTime && m.ZhushouExpiry > currentTime))
                {
                    m.ShowStatus = "使用中";
                }
                else if (m.CesuanExpiry.HasValue && m.CesuanExpiry > createTime && m.CesuanExpiry < currentTime)
                {
                    m.ShowStatus = "成本测算已到期";
                }
                else if (m.ZhushouExpiry.HasValue && m.ZhushouExpiry > createTime && m.ZhushouExpiry < currentTime)
                {
                    m.ShowStatus = "成本助手已到期";
                }
                else
                {
                    m.ShowStatus = "新用户";
                }
            }

            // 筛选逻辑（状态+微信名）
            if (statusFilter != "all")
            {
                members = members.Where(m => m.ShowStatus == statusFilter).ToList();
            }
            if (!string.IsNullOrEmpty(nickname))
            {
                members = members.Where(m => m.Nickname.Contains(nickname)).ToList();
            }

            return View(members);
        }

        // 更新VIP状态（设置权限到期时间）
        [HttpPost]
        public async Task<IActionResult> UpdateVipStatus(int userId, int permId, DateTime expiryTime)
        {
            using (var transaction = await _context.Database.BeginTransactionAsync())
            {
                try
                {
                    // 原有逻辑：更新 UserPermissions
                    var permission = await _context.UserPermissions
                        .FirstOrDefaultAsync(p => p.UserId == userId && p.PermId == permId);
                    if (permission != null)
                    {
                        permission.GrantTime = expiryTime;
                    }
                    else
                    {
                        _context.UserPermissions.Add(new UserPermission
                        {
                            UserId = userId,
                            PermId = permId,
                            GrantTime = expiryTime
                        });
                    }

                    // 更新 Users
                    var user = await _context.Users.FindAsync(userId);
                    if (user != null)
                    {
                        user.Status = 1;
                    }

                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync(); // 两表操作都成功才提交
                    return RedirectToAction("Members");
                }
                catch (DbUpdateException ex)
                {
                    await transaction.RollbackAsync(); // 失败则回滚所有操作
                    TempData["ErrorMessage"] = "操作失败，请重试";
                    return RedirectToAction("Members");
                }
            }
        }
    }
}