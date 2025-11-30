using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace 峰哥造价课堂WEB.Models
{
    public class DownloadFile
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        [Column("FileName")]  // 指定数据库列名
        public string FileName { get; set; } = string.Empty;

        [StringLength(500)]
        [Column("Description")]
        public string Description { get; set; } = string.Empty;

        [Required]
        [Column("FilePath")]  // 指定数据库列名
        public string FilePath { get; set; } = string.Empty;

        [Required]
        [StringLength(20)]
        [Column("FileType")]
        public string FileType { get; set; } = "exe";

        [Required]
        [StringLength(20)]
        [Column("RequiredRole")]
        public string RequiredRole { get; set; } = "User";

        [Column("UploadDate")]
        public DateTime UploadDate { get; set; } = DateTime.Now;

        [Column("DownloadCount")]
        public int DownloadCount { get; set; } = 0;

        [Column("FileSize")]
        public long FileSize { get; set; }

        [StringLength(20)]
        [Column("Version")]
        public string Version { get; set; } = "1.0.0";
    }
}