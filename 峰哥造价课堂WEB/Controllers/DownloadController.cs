using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;
using 峰哥造价课堂WEB.Services;

namespace 峰哥造价课堂WEB.Controllers
{
    public class DownloadController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IAuthService _authService;
        private readonly FileService _fileService;
        private readonly IWebHostEnvironment _environment;

        public DownloadController(ApplicationDbContext context, IAuthService authService,
                                FileService fileService, IWebHostEnvironment environment)
        {
            _context = context;
            _authService = authService;
            _fileService = fileService;
            _environment = environment;
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                var currentUserRole = _authService.GetCurrentUserRole();
                var accessibleRoles = GetAccessibleRoles(currentUserRole);

                // 修复LINQ查询
                var files = await _context.DownloadFiles
                    .Where(f => accessibleRoles.Contains(f.RequiredRole))
                    .OrderByDescending(f => f.UploadDate)
                    .ToListAsync();

                ViewBag.CanUpload = currentUserRole == "Admin";
                return View(files);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Download/Index错误: {ex.Message}");
                ViewBag.CanUpload = false;
                return View(new List<DownloadFile>());
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
        public async Task<IActionResult> Upload(IFormFile file, DownloadFile downloadFile)
        {
            if (file == null || file.Length == 0)
            {
                ViewBag.Error = "请选择文件";
                return View(downloadFile);
            }

            try
            {
                // 验证文件类型
                var allowedExtensions = new[] { ".exe", ".msi", ".zip", ".rar", ".pdf", ".doc", ".docx" };
                var fileExtension = Path.GetExtension(file.FileName).ToLower();

                if (!allowedExtensions.Contains(fileExtension))
                {
                    ViewBag.Error = "不支持的文件格式";
                    return View(downloadFile);
                }

                // 验证文件大小（50MB限制）
                if (file.Length > 50 * 1024 * 1024)
                {
                    ViewBag.Error = "文件大小不能超过50MB";
                    return View(downloadFile);
                }

                var filePath = await _fileService.SaveDownloadFileAsync(file);

                downloadFile.FilePath = filePath;
                downloadFile.UploadDate = DateTime.Now;
                downloadFile.FileSize = file.Length;
                downloadFile.DownloadCount = 0;

                _context.DownloadFiles.Add(downloadFile);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "文件上传成功！";
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"上传失败: {ex.Message}";
                return View(downloadFile);
            }
        }

        public async Task<IActionResult> Download(int id)
        {
            try
            {
                var file = await _context.DownloadFiles.FindAsync(id);
                if (file == null)
                {
                    return NotFound();
                }

                // 权限检查：Guest 角色也能下载标记为 Guest 的文件
                var currentUserRole = _authService.GetCurrentUserRole();
                if (!CanUserAccessFile(currentUserRole, file.RequiredRole))
                {
                    return RedirectToAction("AccessDenied", "Account");
                }

                // 更新下载计数
                file.DownloadCount++;
                await _context.SaveChangesAsync();

                var path = Path.Combine(_environment.WebRootPath, file.FilePath.TrimStart('/'));
                if (!System.IO.File.Exists(path))
                {
                    TempData["ErrorMessage"] = "文件不存在！";
                    return RedirectToAction("Index");
                }

                var memory = new MemoryStream();
                using (var stream = new FileStream(path, FileMode.Open))
                {
                    await stream.CopyToAsync(memory);
                }
                memory.Position = 0;

                // 设置下载文件名
                var downloadFileName = GetDownloadFileName(file.FileName, file.FileType);
                return File(memory, "application/octet-stream", downloadFileName);
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"下载失败: {ex.Message}";
                return RedirectToAction("Index");
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var file = await _context.DownloadFiles.FindAsync(id);
                if (file != null)
                {
                    _fileService.DeleteFile(file.FilePath);
                    _context.DownloadFiles.Remove(file);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "文件删除成功！";
                }
                else
                {
                    TempData["ErrorMessage"] = "文件不存在！";
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"删除失败: {ex.Message}";
            }

            return RedirectToAction("Index");
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

        // 辅助方法：检查用户是否可以访问文件
        private bool CanUserAccessFile(string userRole, string fileRequiredRole)
        {
            var roleHierarchy = new Dictionary<string, int>
            {
                ["Admin"] = 3,
                ["User"] = 2,
                ["Guest"] = 1
            };

            if (roleHierarchy.ContainsKey(userRole) && roleHierarchy.ContainsKey(fileRequiredRole))
            {
                return roleHierarchy[userRole] >= roleHierarchy[fileRequiredRole];
            }

            return false;
        }

        private string GetDownloadFileName(string fileName, string fileType)
        {
            // 如果文件名已经有扩展名，直接返回
            if (!string.IsNullOrEmpty(Path.GetExtension(fileName)))
            {
                return fileName;
            }

            // 根据文件类型添加扩展名
            return fileType.ToLower() switch
            {
                "exe" => fileName + ".exe",
                "msi" => fileName + ".msi",
                "zip" => fileName + ".zip",
                "rar" => fileName + ".rar",
                "pdf" => fileName + ".pdf",
                "doc" => fileName + ".doc",
                "docx" => fileName + ".docx",
                _ => fileName + ".download"
            };
        }
    }

}