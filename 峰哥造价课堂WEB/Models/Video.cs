using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace 峰哥造价课堂WEB.Models
{
    public class Video
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        [Column("title")]  // 指定数据库列名
        public string Title { get; set; } = string.Empty;

        [StringLength(500)]
        [Column("description")]
        public string Description { get; set; } = string.Empty;

        [Required]
        [Column("file_path")]  // 指定数据库列名
        public string FilePath { get; set; } = string.Empty;

        [Column("thumbnail_path")]
        public string ThumbnailPath { get; set; } = string.Empty;

        [Required]
        [Column("required_role")]
        public string RequiredRole { get; set; } = "";

        [Column("is_public")]
        public bool IsPublic { get; set; } = false;

        [Column("upload_date")]
        public DateTime UploadDate { get; set; } = DateTime.Now;

        [Column("file_size")]
        public long FileSize { get; set; }

        [Column("view_count")]
        public int ViewCount { get; set; } = 0;
    }
}