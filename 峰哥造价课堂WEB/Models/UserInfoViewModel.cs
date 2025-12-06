using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using 峰哥造价课堂WEB.Data; // 引入数据库上下文命名空间

public class UserInfoViewModel
{
    [Required(ErrorMessage = "用户名不能为空")]
    [StringLength(32, ErrorMessage = "用户名长度不能超过32个字符")]
    [Remote(action: "CheckUserNameUnique", controller: "Account",
        AdditionalFields = nameof(OpenId),
        ErrorMessage = "用户名已被占用，请更换")] // 远程验证
    public string UserName { get; set; }

    // 其他属性保持不变...
    [Required(ErrorMessage = "密码不能为空")]
    [StringLength(20, MinimumLength = 6, ErrorMessage = "密码长度必须在6-20个字符之间")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Compare("Password", ErrorMessage = "两次输入的密码不一致")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }

    public string OpenId { get; set; } = string.Empty;
}