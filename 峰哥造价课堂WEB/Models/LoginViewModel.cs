// 路径：ketangWeb/峰哥造价课堂WEB/Models/LoginViewModel.cs
using System.ComponentModel.DataAnnotations;

namespace 峰哥造价课堂WEB.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "用户名不能为空")]
        [Display(Name = "用户名")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "密码不能为空")]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "记住我")]
        public bool RememberMe { get; set; }

        // 用于传递登录后的跳转地址
        public string? ReturnUrl { get; set; }
    }
}