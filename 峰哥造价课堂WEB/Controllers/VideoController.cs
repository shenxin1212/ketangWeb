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
                var accessibleRoles = GetAccessibleRoles(currentUserRole);

                // 修复LINQ查询，避免使用自定义方法
                var videos = await _context.Videos
                    .Where(v => v.IsPublic || accessibleRoles.Contains(v.RequiredRole))
                    .OrderByDescending(v => v.UploadDate)
                    .ToListAsync();

                ViewBag.CanUpload = currentUserRole == "Admin";
                return View(videos);
            }
            catch (Exception ex)
            {
                // 记录错误
                Console.WriteLine($"Video/Index错误: {ex.Message}");

                // 返回空列表
                ViewBag.CanUpload = false;
                return View(new List<Video>());
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult Upload()
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile videoFile, Video video)
        {
            if (videoFile == null || videoFile.Length == 0)
            {
                ViewBag.Error = "请选择视频文件";
                return View(video);
            }

            try
            {
                // 验证文件类型
                var allowedExtensions = new[] { ".mp4", ".avi", ".mov", ".wmv" };
                var fileExtension = Path.GetExtension(videoFile.FileName).ToLower();

                if (!allowedExtensions.Contains(fileExtension))
                {
                    ViewBag.Error = "不支持的文件格式，请选择MP4、AVI、MOV或WMV格式";
                    return View(video);
                }

                // 验证文件大小（100MB限制）
                if (videoFile.Length > 100 * 1024 * 1024)
                {
                    ViewBag.Error = "文件大小不能超过100MB";
                    return View(video);
                }

                var filePath = await _fileService.SaveVideoAsync(videoFile);

                video.FilePath = filePath;
                video.UploadDate = DateTime.Now;
                video.FileSize = videoFile.Length;

                // 设置默认缩略图路径
                if (string.IsNullOrEmpty(video.ThumbnailPath))
                {
                    video.ThumbnailPath = "/images/video-thumbnail.jpg"; // 默认缩略图
                }

                _context.Videos.Add(video);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "视频上传成功！";
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"上传失败: {ex.Message}";
                return View(video);
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var video = await _context.Videos.FindAsync(id);
                if (video != null)
                {
                    // 删除物理文件
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

                // 检查权限
                var currentUserRole = _authService.GetCurrentUserRole();
                if (!video.IsPublic && !CanUserAccessVideo(currentUserRole, video.RequiredRole))
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

        // 辅助方法：获取用户有权限的角色列表
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

        // 辅助方法：检查用户是否可以访问视频
        private bool CanUserAccessVideo(string userRole, string videoRequiredRole)
        {
            var roleHierarchy = new Dictionary<string, int>
            {
                ["Admin"] = 3,
                ["User"] = 2,
                ["Guest"] = 1
            };

            if (roleHierarchy.ContainsKey(userRole) && roleHierarchy.ContainsKey(videoRequiredRole))
            {
                return roleHierarchy[userRole] >= roleHierarchy[videoRequiredRole];
            }

            return false;
        }
    }
}