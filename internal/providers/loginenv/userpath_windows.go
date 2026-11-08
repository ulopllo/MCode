//go:build windows

package loginenv

import "golang.org/x/sys/windows/registry"

// windowsUserPath 读取注册表里的用户 PATH（HKCU\Environment\Path）。
// GUI 进程的 PATH 在启动时就固定了：安装器（例如 agy 的 install.ps1）之后写进
// 用户 PATH 的目录不会出现在进程环境里，只有读注册表才能看到最新值。
// 读不到时返回空串，调用方按没有额外目录处理。
func windowsUserPath() string {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	value, _, err := key.GetStringValue("Path")
	if err != nil || value == "" {
		return ""
	}
	// 用户 PATH 通常是 REG_EXPAND_SZ，含 %USERPROFILE% 这类变量。
	expanded, err := registry.ExpandString(value)
	if err != nil {
		return value
	}
	return expanded
}
