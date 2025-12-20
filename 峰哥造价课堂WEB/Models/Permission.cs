// Models/Permission.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace 峰哥造价课堂WEB.Models
{
    public class Permission
    {
        [Column("id")]
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)] // 自增
        [Index(IsUnique = true)] // 唯一约束
        public int Id { get; set; }

        [Column("perm_key")]
        [Required]
        [StringLength(30)]
        public string PermKey { get; set; } = string.Empty;

        [Column("name")]
        [Required]
        [StringLength(50)]
        public string Name { get; set; } = string.Empty;

        [Column("description")]
        [StringLength(255)]
        public string? Description { get; set; }
    }
}