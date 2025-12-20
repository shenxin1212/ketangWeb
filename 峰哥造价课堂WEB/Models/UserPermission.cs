using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace 峰哥造价课堂WEB.Models
{
    [Table("user_permission")]
    [PrimaryKey(nameof(UserId), nameof(PermId))] // 复合主键配置
    public class UserPermission
    {
        [Column("user_id")]
        public int UserId { get; set; } // 关联用户ID

        [Column("perm_id")]
        public int PermId { get; set; }  // 1=成本测算, 2=成本助手

        [Column("grant_time")]
        public DateTime GrantTime { get; set; } // 权限到期时间

        // 导航属性（关联用户）
        public User User { get; set; } = null!;

        // 导航属性（关联用户）
        public Permission Permission { get; set; } = null!;
    }
}