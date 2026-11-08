//go:build !windows

package loginenv

// windowsUserPath 在非 Windows 平台没有注册表用户 PATH 需要补：
// 登录 Shell 读到的 PATH 已经是最新值。
func windowsUserPath() string {
	return ""
}
