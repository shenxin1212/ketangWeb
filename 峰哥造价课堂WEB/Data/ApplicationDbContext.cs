using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Video> Videos { get; set; }
        public DbSet<DownloadFile> DownloadFiles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            // 这一行配置可以让所有string类型的NULL值自动转为空字符串
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                foreach (var property in entityType.GetProperties())
                {
                    if (property.ClrType == typeof(string))
                    {
                        property.SetColumnType("varchar(" + (property.GetMaxLength() ?? 255) + ")");
                        // 设置默认值为空字符串
                        modelBuilder.Entity(entityType.ClrType)
                            .Property(property.Name)
                            .HasDefaultValue("");
                    }
                }
            }

            // 配置User表
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("user");
                entity.HasKey(e => e.Id);

                entity.HasIndex(e => e.OpenId)
                    .IsUnique()
                    .HasDatabaseName("uniq_openid");

                entity.HasIndex(e => e.Mobile)
                    .HasDatabaseName("idx_mobile");

                entity.HasIndex(e => e.UnionId)
                    .HasDatabaseName("idx_unionid");

                entity.Property(e => e.Id)
                    .HasColumnName("id")
                    .ValueGeneratedOnAdd();

                entity.Property(e => e.OpenId)
                    .HasColumnName("openid")
                    .HasMaxLength(32);

                entity.Property(e => e.UnionId)
                    .HasColumnName("unionid")
                    .HasMaxLength(32);

                entity.Property(e => e.Nickname)
                    .HasColumnName("nickname")
                    .HasMaxLength(64)
                    .HasDefaultValue("");

                entity.Property(e => e.Avatar)
                    .HasColumnName("avatar")
                    .HasMaxLength(255)
                    .HasDefaultValue("");

                entity.Property(e => e.Mobile)
                    .HasColumnName("mobile")
                    .HasMaxLength(15);

                entity.Property(e => e.CreateTime)
                    .HasColumnName("create_time")
                    .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.UpdateTime)
                    .HasColumnName("update_time")
                    .HasDefaultValueSql("CURRENT_TIMESTAMP");

                entity.Property(e => e.Status)
                    .HasColumnName("status")
                    .HasDefaultValue(1);

                entity.Property(e => e.AuthToken)
                    .HasColumnName("AuthToken")
                    .HasMaxLength(100);

                entity.Property(e => e.TokenExpiry)
                    .HasColumnName("TokenExpiry");

                entity.Property(e => e.UserName)
                    .HasColumnName("userName")
                    .HasMaxLength(32);

                // 添加角色字段（如果表中没有，需要手动添加）
                entity.Property(e => e.Role)
                    .HasColumnName("role")
                    .HasDefaultValue("User");

                entity.Property(e => e.IsActive)
                    .HasColumnName("is_active")
                    .HasDefaultValue(true);
            });

            modelBuilder.Entity<Video>().ToTable("Videos");
            modelBuilder.Entity<DownloadFile>().ToTable("DownloadFiles");
        }
    }
}