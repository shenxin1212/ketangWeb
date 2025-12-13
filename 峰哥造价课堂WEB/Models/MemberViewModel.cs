// Models/MemberViewModel.cs
namespace 峰哥造价课堂WEB.Models
{
    public class MemberViewModel
    {
        public int Id { get; set; }
        public string Nickname { get; set; } = string.Empty;
        public DateTime? CesuanExpiry { get; set; } // 成本测算到期时间
        public DateTime? ZhushouExpiry { get; set; } // 成本助手到期时间
        public DateTime CreateTime { get; set; }
        public string Status { get; set; } = string.Empty; // 试用状态
        public string ShowStatus { get; set; } = string.Empty; // 综合状态
    }
}