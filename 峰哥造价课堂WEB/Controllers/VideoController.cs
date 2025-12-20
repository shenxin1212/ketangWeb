using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using 峰哥造价课堂WEB.Services;

namespace 峰哥造价课堂WEB.Controllers
{
    [Authorize]
    public class VideoController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IAuthService _authService;
        private readonly FileService _fileService;

        public VideoController(ApplicationDbContext context, IAuthService authService, FileService fileService)
        {
            _context = context;
            _authService = authService;
            _fileService = fileService;
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                var currentUserRole = _authService.GetCurrentUserRole();
                var user = await _authService.GetCurrentUserAsync();

                // 获取用户拥有的所有权限角色（包括其自身角色及可访问的角色）
                var userAccessibleRoles = GetUserAccessibleRoles(user);

                // 视频查询：公开视频或用户有权访问的角色视频
                var videos = await _context.Videos
                    .Where(v => v.IsPublic || userAccessibleRoles.Contains(v.RequiredRole))
                    .OrderByDescending(v => v.UploadDate)
                    .ToListAsync();

                // 检查上传权限：管理员或拥有视频上传权限的用户
                var canUpload = currentUserRole == "Admin" || await _authService.HasPermissionAsync("video.upload");
                ViewBag.CanUpload = canUpload;

                // 检查管理权限
                ViewBag.CanManage = currentUserRole == "Admin" || await _authService.HasPermissionAsync("video.manage");

                return View(videos);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Video/Index错误: {ex.Message}");
                ViewBag.CanUpload = false;
                ViewBag.CanManage = false;
                return View(new List<Video>());
            }
        }

        [HttpGet]
        public async Task<IActionResult> Upload()
        {
            // 检查上传权限
            var currentUserRole = _authService.GetCurrentUserRole();
            if (currentUserRole != "Admin" && !await _authService.HasPermissionAsync("video.upload"))
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            // 获取用户可分配的角色列表（不能超过自身角色级别）
            var user = await _authService.GetCurrentUserAsync();
            ViewBag.AvailableRoles = GetAssignableRoles(user.SafeRole);

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile videoFile, Video video)
        {
            // 检查上传权限
            var currentUserRole = _authService.GetCurrentUserRole();
            if (currentUserRole != "Admin" && !await _authService.HasPermissionAsync("video.upload"))
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            if (videoFile == null || videoFile.Length == 0)
            {
                ViewBag.Error = "请选择视频文件";
                ViewBag.AvailableRoles = GetAssignableRoles(currentUserRole);
                return View(video);
            }

            try
            {
                // 验证文件类型和大小（保持原有逻辑）
                var allowedExtensions = new[] { ".mp4", ".avi", ".mov", ".wmv" };
                var fileExtension = Path.GetExtension(videoFile.FileName).ToLower();

                if (!allowedExtensions.Contains(fileExtension))
                {
                    ViewBag.Error = "不支持的文件格式，请选择MP4、AVI、MOV或WMV格式";
                    ViewBag.AvailableRoles = GetAssignableRoles(currentUserRole);
                    return View(video);
                }

                if (videoFile.Length > 100 * 1024 * 1024)
                {
                    ViewBag.Error = "文件大小不能超过100MB";
                    ViewBag.AvailableRoles = GetAssignableRoles(currentUserRole);
                    return View(video);
                }

                var filePath = await _fileService.SaveVideoAsync(videoFile);

                video.FilePath = filePath;
                video.UploadDate = DateTime.Now;
                video.FileSize = videoFile.Length;

                // 设置默认缩略图路径
                if (string.IsNullOrEmpty(video.ThumbnailPath))
                {
                    video.ThumbnailPath = "/images/video-thumbnail.jpg";
                }

                // 验证用户是否有权限设置该RequiredRole
                var user = await _authService.GetCurrentUserAsync();
                var assignableRoles = GetAssignableRoles(user.SafeRole);
                if (!assignableRoles.Contains(video.RequiredRole))
                {
                    // 如果用户没有权限设置该角色，则默认使用用户自身角色
                    video.RequiredRole = user.SafeRole;
                }

                _context.Videos.Add(video);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "视频上传成功！";
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"上传失败: {ex.Message}";
                ViewBag.AvailableRoles = GetAssignableRoles(currentUserRole);
                return View(video);
            }
        }

        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            // 检查管理权限
            var currentUserRole = _authService.GetCurrentUserRole();
            if (currentUserRole != "Admin" && !await _authService.HasPermissionAsync("video.manage"))
            {
                TempData["ErrorMessage"] = "没有删除视频的权限";
                return RedirectToAction("Index");
            }

            try
            {
                var video = await _context.Videos.FindAsync(id);
                if (video != null)
                {
                    if (!string.IsNullOrEmpty(video.FilePath))
                    {
                        _fileService.DeleteFile(video.FilePath);
                    }

                    _context.Videos.Remove(video);
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "视频删除成功！";
                }
                else
                {
                    TempData["ErrorMessage"] = "视频不存在！";
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"删除失败: {ex.Message}";
            }

            return RedirectToAction("Index");
        }

        // 视频播放页面
        public async Task<IActionResult> Play(int id)
        {
            try
            {
                var video = await _context.Videos.FindAsync(id);
                if (video == null)
                {
                    return NotFound();
                }

                // 检查权限：公开视频或用户有权访问
                var user = await _authService.GetCurrentUserAsync();
                var hasAccess = video.IsPublic ||
                               HasVideoAccessPermission(user, video.RequiredRole);

                if (!hasAccess)
                {
                    return RedirectToAction("AccessDenied", "Account");
                }

                // 增加观看次数
                video.ViewCount++;
                await _context.SaveChangesAsync();

                return View(video);
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"加载视频失败: {ex.Message}";
                return RedirectToAction("Index");
            }
        }

        // 辅助方法：获取用户可访问的所有角色（基于用户角色和权限）
        private string[] GetUserAccessibleRoles(User? user)
        {
            if (user == null)
            {
                return new[] { "Guest" };
            }

            // 结合用户权限扩展可访问角色（如果有特定权限可以访问更高角色的视频）
            var accessibleRoles = new HashSet<string>();

            var validPermissions = user.UserPermissions
            .Where(up => up.GrantTime >= DateTime.Now) // 权限未过期（GrantTime >= 当前时间）
            .ToList();

            // 将有效的权限ID添加到可访问角色列表中
            foreach (var perm in validPermissions)
            {
                accessibleRoles.Add(perm.PermId.ToString());  // 存入PermId（转为字符串，因为原列表是string类型）
            }

            return accessibleRoles.ToArray();
        }

        // 辅助方法：检查用户是否有访问该视频的权限
        private bool HasVideoAccessPermission(User? user, string videoRequiredRole)
        {
            if (user == null)
            {
                return videoRequiredRole == "Guest";
            }

            // 管理员拥有所有权限
            if (user.IsAdmin)
            {
                return true;
            }

            //// 检查用户角色是否足够
            //var roleHierarchy = GetRoleHierarchy();
            //if (roleHierarchy.TryGetValue(user.SafeRole, out int userRoleLevel) &&
            //    roleHierarchy.TryGetValue(videoRequiredRole, out int requiredLevel))
            //{
            //    if (userRoleLevel >= requiredLevel)
            //    {
            //        return true;
            //    }
            //}

            // 检查用户是否有特定权限可以访问该角色的视频
            // 格式：video.access.{role} 例如：video.access.VIP
            var requiredPermission = $"video.access.{videoRequiredRole.ToLower()}";
            return user.UserPermissions.Any(up => up.Permission.PermKey == requiredPermission);
        }

        // 辅助方法：获取用户可分配的角色（不能超过自身角色级别）
        private string[] GetAssignableRoles(string userRole)
        {
            var roleHierarchy = GetRoleHierarchy();
            var userRoleLevel = roleHierarchy.TryGetValue(userRole, out int level) ? level : 0;

            return roleHierarchy
                .Where(r => r.Value <= userRoleLevel)
                .Select(r => r.Key)
                .ToArray();
        }

        // 角色层级定义（复用逻辑，统一维护）
        private Dictionary<string, int> GetRoleHierarchy()
        {
            return new Dictionary<string, int>
            {
                ["Admin"] = 3,
                ["User"] = 2,
                ["Guest"] = 1
            };
        }

    }
}