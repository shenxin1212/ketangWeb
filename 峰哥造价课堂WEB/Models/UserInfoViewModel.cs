using System.ComponentModel.DataAnnotations;

public class UserInfoViewModel
{
    [Required(ErrorMessage = "用户名不能为空")]
    [StringLength(32, ErrorMessage = "用户名长度不能超过32个字符")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "密码不能为空")]
    [StringLength(20, MinimumLength = 6, ErrorMessage = "密码长度必须在6-20个字符之间")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Compare("Password", ErrorMessage = "两次输入的密码不一致")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }

    // 用于关联用户的 openId（不显示在表单，仅用于后端查询）
    public string OpenId { get; set; } = string.Empty;
}