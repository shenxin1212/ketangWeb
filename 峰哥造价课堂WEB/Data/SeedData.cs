using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context)
        {
            // 添加默认管理员用户（如果不存在）
            if (!context.Users.Any(u => u.Role == "Admin"))
            {
                var adminUser = new User
                {
                    OpenId = "admin_openid",
                    UnionId = "admin_unionid",
                    Nickname = "系统管理员",
                    Avatar = "",
                    Mobile = "13800000000",
                    UserName = "admin",
                    Role = "Admin",
                    Status = 1,
                    IsActive = true,
                    CreateTime = DateTime.Now,
                    UpdateTime = DateTime.Now,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123"),
                    AuthToken = "1234",  // 明确设置为空字符串
                    TokenExpiry = DateTime.Now  
                };
                await context.Users.AddAsync(adminUser);
            }

            // 添加测试用户
            if (!context.Users.Any(u => u.Role == "User"))
            {
                var testUser = new User
                {
                    OpenId = "user_openid",
                    UnionId = "user_unionid",
                    Nickname = "测试用户",
                    Avatar = "",
                    Mobile = "13900000000",
                    UserName = "user1",
                    Role = "User",
                    Status = 1,
                    IsActive = true,
                    CreateTime = DateTime.Now,
                    UpdateTime = DateTime.Now,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("user123"),
                    AuthToken = "",  // 明确设置为空字符串
                    TokenExpiry = DateTime.Now    // 明确设置为null
                };
                await context.Users.AddAsync(testUser);
            }

            // 视频种子数据
            if (!context.Videos.Any())
            {
                var videos = new Video[]
                {
                    new Video
                    {
                        Title = "公开演示视频",
                        Description = "这是一个公开的视频，所有用户都可以观看",
                        FilePath = "/uploads/videos/demo1.mp4",
                        RequiredRole = "Guest",
                        IsPublic = true,
                        UploadDate = DateTime.Now,
                        FileSize = 1024000,
                        ViewCount = 0
                    },
                    new Video
                    {
                        Title = "会员专属视频",
                        Description = "只有注册用户和管理员可以观看此视频",
                        FilePath = "/uploads/videos/demo2.mp4",
                        RequiredRole = "User",
                        IsPublic = false,
                        UploadDate = DateTime.Now,
                        FileSize = 2048000,
                        ViewCount = 0
                    }
                };
                await context.Videos.AddRangeAsync(videos);
            }

            // 下载文件种子数据
            if (!context.DownloadFiles.Any())
            {
                var files = new DownloadFile[]
                {
                    new DownloadFile
                    {
                        FileName = "视频播放器安装包",
                        Description = "支持多种格式的视频播放器",
                        FilePath = "/uploads/files/VideoPlayer.exe",
                        FileType = "exe",
                        RequiredRole = "User",
                        UploadDate = DateTime.Now,
                        DownloadCount = 0,
                        FileSize = 5120000,
                        Version = "2.1.0"
                    }
                };
                await context.DownloadFiles.AddRangeAsync(files);
            }

            await context.SaveChangesAsync();
        }
    }
}