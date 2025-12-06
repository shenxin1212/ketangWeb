// 路径：ketangWeb/峰哥造价课堂WEB/Models/LoginViewModel.cs
using System.ComponentModel.DataAnnotations;

namespace 峰哥造价课堂WEB.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "请输入用户名")]
        [Display(Name = "用户名")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "请输入密码")]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "记住我")]
        public bool RememberMe { get; set; }

        // 用于传递登录后的跳转地址
        public string? ReturnUrl { get; set; }
    }
}