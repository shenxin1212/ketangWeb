using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context)
        {
            // 在 SeedData.cs 的下载文件种子数据中添加
            if (!context.DownloadFiles.Any())
            {
                var files = new DownloadFile[]
                {
        // 公共应用程序（游客可下载）
        new DownloadFile
        {
            FileName = "造价计算器",
            Description = "无需登录即可使用的造价计算工具",
            FilePath = "/uploads/files/CostCalculator.exe",
            FileType = "exe",
            RequiredRole = "Guest", // 关键：设置为 Guest 角色可访问
            UploadDate = DateTime.Now,
            DownloadCount = 0,
            FileSize = 8192000, // 8MB
            Version = "1.0.0"
        },
        // 原有其他文件（User/Admin 可访问）
        new DownloadFile
        {
            FileName = "视频播放器安装包",
            Description = "支持多种格式的视频播放器",
            FilePath = "/uploads/files/VideoPlayer.exe",
            FileType = "exe",
            RequiredRole = "User", // 登录用户可访问
            UploadDate = DateTime.Now,
            DownloadCount = 0,
            FileSize = 5120000,
            Version = "2.1.0"
        }
                };
                await context.DownloadFiles.AddRangeAsync(files);
            }
        }
    }
}