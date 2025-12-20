using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace 峰哥造价课堂WEB.Models
{
    public class User
    {
        [Column("id")]
        public int Id { get; set; }

        [StringLength(32)]
        [Column("openid")]
        public string? OpenId { get; set; } = string.Empty;

        [StringLength(32)]
        [Column("unionid")]
        public string? UnionId { get; set; } = string.Empty;

        [StringLength(64)]
        [Column("nickname")]
        public string? Nickname { get; set; } = string.Empty;

        [StringLength(255)]
        [Column("avatar")]
        public string? Avatar { get; set; } = string.Empty;

        [StringLength(15)]
        [Column("mobile")]
        public string? Mobile { get; set; } = string.Empty;

        [Column("create_time")]
        public DateTime? CreateTime { get; set; } = DateTime.Now;

        [Column("update_time")]
        public DateTime? UpdateTime { get; set; } = DateTime.Now;

        [Column("status")]
        public byte? Status { get; set; } = 1;

        [StringLength(100)]
        [Column("AuthToken")]
        public string? AuthToken { get; set; } = string.Empty;

        [Column("TokenExpiry")]
        public DateTime? TokenExpiry { get; set; }

        [StringLength(32)]
        [Column("userName")]
        public string? UserName { get; set; } = string.Empty;

        // 系统角色字段
        [Required]
        [Column("role")]
        public string? Role { get; set; } = "User";

        [Column("is_active")]
        public bool IsActive { get; set; } = true;

        // 添加PasswordHash属性用于兼容现有代码
        [StringLength(255)]
        [Column("password_hash")]
        public string? PasswordHash { get; set; } = string.Empty;

        // 安全访问属性 - 防止NULL值导致的异常
        [NotMapped]
        public string? SafeOpenId => OpenId ?? "";

        [NotMapped]
        public string SafeUnionId => UnionId ?? "";

        [NotMapped]
        public string SafeNickname => Nickname ?? "匿名用户";

        [NotMapped]
        public string SafeAvatar => Avatar ?? "/images/default-avatar.jpg";

        [NotMapped]
        public string SafeMobile => Mobile ?? "";

        [NotMapped]
        public string SafeAuthToken => AuthToken ?? "";

        [NotMapped]
        public string SafeUserName => UserName ?? "未知用户";

        [NotMapped]
        public string SafeRole => Role ?? "User";

        [NotMapped]
        public string SafePasswordHash => PasswordHash ?? "";

        // 便捷属性
        [NotMapped]
        public bool IsAdmin => SafeRole == "Admin";

        [NotMapped]
        public bool HasPassword => !string.IsNullOrEmpty(SafePasswordHash);

        // 添加是否已完善信息的属性
        [NotMapped]
        public bool IsInfoCompleted => !string.IsNullOrEmpty(SafeUserName) && !string.IsNullOrEmpty(SafePasswordHash);

        public ICollection<UserPermission> UserPermissions { get; set; } = new List<UserPermission>();

    }
}