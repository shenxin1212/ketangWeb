// Controllers/PermissionController.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using 峰哥造价课堂WEB.Data;
using 峰哥造价课堂WEB.Models;

namespace 峰哥造价课堂WEB.Controllers
{
    [Authorize(Roles = "Admin")]
    public class PermissionController : Controller
    {
        private readonly ApplicationDbContext _context;

        public PermissionController(ApplicationDbContext context)
        {
            _context = context;
        }

        // 权限列表
        public async Task<IActionResult> Index()
        {
            var permissions = await _context.Permissions.ToListAsync();
            return View(permissions);
        }

        // 创建权限（GET）
        public IActionResult Create()
        {
            return View();
        }

        // 创建权限（POST）
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Permission permission)
        {
            if (ModelState.IsValid)
            {
                // 检查perm_key是否已存在
                if (await _context.Permissions.AnyAsync(p => p.PermKey == permission.PermKey))
                {
                    ModelState.AddModelError("PermKey", "权限标识已存在");
                    return View(permission);
                }

                _context.Add(permission);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(permission);
        }

        // 编辑权限（GET）
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();
            var permission = await _context.Permissions.FindAsync(id);
            return permission == null ? NotFound() : View(permission);
        }

        // 编辑权限（POST）
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Permission permission)
        {
            if (id != permission.Id) return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    // 检查perm_key是否与其他权限冲突
                    if (await _context.Permissions.AnyAsync(p => p.PermKey == permission.PermKey && p.Id != id))
                    {
                        ModelState.AddModelError("PermKey", "权限标识已存在");
                        return View(permission);
                    }

                    _context.Update(permission);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!PermissionExists(permission.Id)) return NotFound();
                    throw;
                }
                return RedirectToAction(nameof(Index));
            }
            return View(permission);
        }

        // 删除权限
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var permission = await _context.Permissions.FindAsync(id);
            if (permission != null)
            {
                // 先删除关联数据
                var userPermissions = await _context.UserPermissions
                    .Where(up => up.PermId == id)
                    .ToListAsync();
                _context.UserPermissions.RemoveRange(userPermissions);

                _context.Permissions.Remove(permission);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }

        private bool PermissionExists(int id) => _context.Permissions.Any(e => e.Id == id);
    }
}