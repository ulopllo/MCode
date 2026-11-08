package loginenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"mcode/internal/procattr"
	"mcode/internal/startuptrace"
)

// 忽略终端、会话相关以及外部注入的环境变量，保持环境纯净。
var excludedKeys = map[string]bool{
	"_":                      true,
	"SHLVL":                  true,
	"PWD":                    true,
	"OLDPWD":                 true,
	"TERM":                   true,
	"TERM_PROGRAM":           true,
	"TERM_PROGRAM_VERSION":   true,
	"TERM_SESSION_ID":        true,
	"COLORTERM":              true,
	"ITERM_SESSION_ID":       true,
	"XPC_SERVICE_NAME":       true,
	"__CFBundleIdentifier":   true,
	"CLAUDECODE":             true,
	"CLAUDE_CODE_ENTRYPOINT": true,
	"CLAUDE_CODE_SSE_PORT":   true,
}

const retryInterval = 30 * time.Second

var (
	cacheMu     sync.RWMutex
	loaded      bool
	loading     bool
	loadFailed  bool
	lastAttempt time.Time
	cachedEnv   []string
	cachedPath  string

	// loadMu 只负责串行化真正的加载过程：加载期间不持有 cacheMu 的写锁，
	// 这样 currentPATH、LoginEnvReady 这类只读缓存的调用方不会被登录 Shell 阻塞。
	loadMu sync.Mutex

	// loadFunc 提供包级可替换钩子，方便单元测试注入自定义加载逻辑。
	loadFunc func() ([]string, error)

	// systemProxyFunc 提供包级可替换钩子，方便单元测试注入系统代理读取结果。
	systemProxyFunc = systemProxyEnvironment

	// userPathFunc 提供包级可替换钩子，方便单元测试注入注册表里的用户 PATH。
	userPathFunc = windowsUserPath
)

// Environ 返回用户登录 Shell 环境的键值对列表（如 "KEY=VALUE"）。
// 该环境在首次访问时执行登录 Shell 读取并缓存；若读取失败则自动回退到当前进程的环境变量，并在后续调用或查找命令时重试。
func Environ() []string {
	ensureLoaded()
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	res := make([]string, len(cachedEnv))
	copy(res, cachedEnv)
	return res
}

// PATH 返回缓存登录环境中解析并扩充后的 PATH 字符串。
func PATH() string {
	ensureLoaded()
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return cachedPath
}

// LookPath 在登录环境的 PATH 中查找可执行程序。
// 若 name 包含路径分隔符 '/'，直接按文件路径校验其可执行性；
// 否则在登录 PATH 包含的各目录下按顺序搜索首个匹配的可执行文件。
// 若此前加载失败且已过重试间隔，在未查找到时同步重新加载一次再查。
func LookPath(name string) (string, error) {
	if hasPathSeparator(name) {
		if path, ok := lookPathIn("", name); ok {
			return path, nil
		}
		return "", exec.ErrNotFound
	}

	ensureLoaded()
	if path, ok := lookPathIn(currentPATH(), name); ok {
		return path, nil
	}

	cacheMu.RLock()
	needRetry := loadFailed && (time.Since(lastAttempt) >= retryInterval || loading)
	cacheMu.RUnlock()

	if needRetry {
		performLoad(false)
	}
	if path, ok := lookPathIn(currentPATH(), name); ok {
		return path, nil
	}
	return "", exec.ErrNotFound
}

// ProbePath 不等待登录环境加载即可给出可执行程序是否可用的临时结论，供启动路径上的
// Available() 使用：真实加载登录 Shell 要起一次 `-l -i -c` 子进程，不能挡在供应商列表前面。
// 无论哪种情况都会在需要时启动一次后台加载，返回值含义：
//   - found=true 表示已找到（结论确定）；
//   - found=false 且 decided=true 表示登录环境已加载完成、确实找不到，是最终结论；
//   - found=false 且 decided=false 表示登录环境还在后台加载，调用方应先按可用处理，
//     等加载完成后的下一次调用再纠正。
func ProbePath(name string) (found, decided bool) {
	if hasPathSeparator(name) {
		// 显式路径不需要登录环境，结论立即确定。
		_, ok := lookPathIn("", name)
		return ok, true
	}

	ensureLoadedAsync()
	if _, ok := lookPathIn(currentPATH(), name); ok {
		return true, true
	}
	return false, LoginEnvReady()
}

// LoginEnvReady 报告登录环境是否已加载完成。未完成时调用方不能把
// ProbePath 返回的「没找到」当作最终结论。
func LoginEnvReady() bool {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return loaded
}

// hasPathSeparator 判断 name 是否已经是显式路径而不是裸命令名。
// Windows 上 '/' 与 '\' 都是分隔符，其余平台只有 '/'。
func hasPathSeparator(name string) bool {
	return strings.ContainsAny(name, "/"+string(filepath.Separator))
}

// lookPathIn 在给定 PATH 字符串中查找可执行程序。
// name 含路径分隔符时直接按文件路径校验其可执行性。
func lookPathIn(path, name string) (string, bool) {
	if hasPathSeparator(name) {
		return resolveExecutable(filepath.Clean(name))
	}

	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		if resolved, ok := resolveExecutable(filepath.Join(dir, name)); ok {
			return resolved, true
		}
	}
	return "", false
}

// windowsExecutableExts 是 Windows 上按 PATHEXT 习惯补全的可执行后缀。
var windowsExecutableExts = []string{".exe", ".cmd", ".bat"}

// resolveExecutable 在候选路径上解析出真正可执行的文件。
// Unix 校验执行权限位；Windows 没有权限位，额外按 .exe/.cmd/.bat 补全同名命令。
func resolveExecutable(candidate string) (string, bool) {
	if isExecutable(candidate) {
		return candidate, true
	}
	if runtime.GOOS == "windows" {
		for _, ext := range windowsExecutableExts {
			if path := candidate + ext; isExecutable(path) {
				return path, true
			}
		}
	}
	return "", false
}

// currentPATH 返回当前可用的 PATH：登录环境已加载时用它的 PATH，否则先用
// 进程自己的 PATH（追加常见安装目录），保证 ProbePath 不等子进程也有东西可查。
func currentPATH() string {
	cacheMu.RLock()
	loadedNow := loaded
	path := cachedPath
	cacheMu.RUnlock()

	if loadedNow {
		if runtime.GOOS == "windows" {
			// Windows 没有登录 Shell，PATH 可能在应用启动后被安装器改写（写入用户注册表）。
			// 每次查找时按最新值重新合并，装完 CLI 不必重启应用。
			return augmentedPath(path)
		}
		return path
	}
	return augmentedPath(os.Getenv("PATH"))
}

// ensureLoadedAsync 在后台触发一次登录环境加载，重复调用只起一个子进程。
func ensureLoadedAsync() {
	cacheMu.RLock()
	ready := (loaded && !loadFailed) || loading || (loaded && loadFailed && time.Since(lastAttempt) < retryInterval)
	cacheMu.RUnlock()
	if ready {
		return
	}

	cacheMu.Lock()
	if (loaded && !loadFailed) || loading || (loaded && loadFailed && time.Since(lastAttempt) < retryInterval) {
		cacheMu.Unlock()
		return
	}
	loading = true
	cacheMu.Unlock()

	go func() {
		performLoad(false)
		cacheMu.Lock()
		loading = false
		cacheMu.Unlock()
		startuptrace.Mark("providers: login env ready")
	}()
}

// HomeDirectory 返回当前用户主目录；解析失败时回退到 HOME 环境变量，仍为空时返回空串。
func HomeDirectory() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return os.Getenv("HOME")
}

// FindBinary 依次解析可执行文件：先在登录 shell 的 PATH 中依次查找 names
// （登录环境含 ~/.local/bin、各 node 全局 bin 等目录，GUI 进程自己的 PATH 通常没有），
// 再在 fallbackDirs 列出的常见安装目录中查找同一个名字。
// 找到时返回可执行文件的路径；都找不到时返回空串与 false。
func FindBinary(names []string, fallbackDirs []string) (string, bool) {
	for _, name := range names {
		if name == "" {
			continue
		}
		if path, err := LookPath(name); err == nil && path != "" {
			return path, true
		}
	}
	for _, dir := range fallbackDirs {
		if dir == "" {
			continue
		}
		for _, name := range names {
			if name == "" || hasPathSeparator(name) {
				continue
			}
			if resolved, ok := resolveExecutable(filepath.Join(dir, name)); ok {
				return resolved, true
			}
		}
	}
	return "", false
}

// ensureLoaded 保证登录环境已被加载并缓存。
// 加载过程只持 loadMu，不持 cacheMu：读缓存的一方（currentPATH、LoginEnvReady）
// 仍能立刻拿到当前状态，不必等登录 Shell 跑完；只有同样要求加载完成的调用方才会在 loadMu 上排队。
// 若此前抓取失败，且距上次尝试已超过 retryInterval，则在后台触发重新加载而不阻塞当前调用方。
func ensureLoaded() {
	cacheMu.RLock()
	ready := loaded
	failed := loadFailed
	attempt := lastAttempt
	isLoading := loading
	cacheMu.RUnlock()

	if ready {
		if failed && !isLoading && time.Since(attempt) >= retryInterval {
			ensureLoadedAsync()
		}
		return
	}

	performLoad(false)
}

// performLoad 执行环境加载与缓存更新。
// force 为 true 时跳过重试时间间隔检查。
func performLoad(force bool) {
	loadMu.Lock()
	defer loadMu.Unlock()

	cacheMu.RLock()
	isLoaded := loaded
	isFailed := loadFailed
	attempt := lastAttempt
	hasGoodEnv := loaded && !loadFailed && len(cachedEnv) > 0
	cacheMu.RUnlock()

	if isLoaded && !force {
		if !isFailed || time.Since(attempt) < retryInterval {
			return
		}
	}

	start := time.Now()
	var env []string
	var err error
	if loadFunc != nil {
		env, err = loadFunc()
	} else {
		env, err = readLoginEnv()
	}
	elapsed := time.Since(start)

	cacheMu.Lock()
	defer cacheMu.Unlock()

	lastAttempt = time.Now()
	loading = false

	if err != nil || len(env) == 0 {
		shell := defaultShell()
		logErr := err
		if logErr == nil {
			logErr = errors.New("环境为空")
		}
		var stderrStr string
		var lErr *loginEnvError
		var exitErr *exec.ExitError
		if errors.As(err, &lErr) {
			stderrStr = lErr.stderr
		} else if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			se := bytes.TrimSpace(exitErr.Stderr)
			if len(se) > 300 {
				se = se[:300]
			}
			stderrStr = string(se)
		}

		if stderrStr != "" {
			log.Printf("登录 shell 环境加载失败 (shell: %s, 耗时: %v, stderr: %s): %v", shell, elapsed, stderrStr, logErr)
		} else {
			log.Printf("登录 shell 环境加载失败 (shell: %s, 耗时: %v): %v", shell, elapsed, logErr)
		}

		// 成功加载后再次失败不会覆盖已有的好缓存
		if hasGoodEnv {
			return
		}

		env = fallbackEnvironment()
		path := extractPath(env)
		cachedEnv = env
		cachedPath = path
		loaded = true
		loadFailed = true
		return
	}

	path := extractPath(env)
	cachedEnv = env
	cachedPath = path
	loaded = true
	loadFailed = false
}

// extractPath 从环境变量列表中提取 PATH 值，若未找到则返回 augmentedPath("")。
func extractPath(env []string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			return strings.TrimPrefix(kv, "PATH=")
		}
	}
	return augmentedPath("")
}

type loginEnvError struct {
	err    error
	stderr string
}

func (e *loginEnvError) Error() string {
	if e.stderr != "" {
		return fmt.Sprintf("%v (stderr: %s)", e.err, e.stderr)
	}
	return e.err.Error()
}

func (e *loginEnvError) Unwrap() error {
	return e.err
}

// defaultShell 返回可用的用户登录 shell 路径。
func defaultShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" || !isExecutable(shell) {
		if isExecutable("/bin/zsh") {
			return "/bin/zsh"
		}
		return "/bin/sh"
	}
	return shell
}

// readLoginEnv 执行登录 shell 抓取环境变量。
// 读取登录环境的规则：
// 1. 使用 $SHELL -l -i -c 执行子进程（-i 使 .zshrc/.bashrc 等交互配置里的 PATH 也被加载）；
// 2. 用专属 marker 包裹 /usr/bin/env -0 输出，避免 shell rc 文件打印内容污染；
// 3. 超时时间设为 8 秒，失败则报错触发 fallback。
// Windows 没有登录 shell 语义，直接走 fallbackEnvironment，不启动子进程（否则必然等满超时）。
func readLoginEnv() ([]string, error) {
	if runtime.GOOS == "windows" {
		return fallbackEnvironment(), nil
	}

	shell := defaultShell()

	marker := "__MCODE_ENVIRONMENT__"
	script := "printf '" + marker + "'; /usr/bin/env -0; printf '" + marker + "'"

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmd := procattr.HideWindow(exec.CommandContext(ctx, shell, "-l", "-i", "-c", script))
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	out, err := cmd.Output()
	if err != nil {
		se := bytes.TrimSpace(stderrBuf.Bytes())
		if len(se) > 300 {
			se = se[:300]
		}
		if len(se) > 0 {
			return nil, &loginEnvError{err: err, stderr: string(se)}
		}
		return nil, err
	}

	markerBytes := []byte(marker)
	startIdx := bytes.Index(out, markerBytes)
	endIdx := bytes.LastIndex(out, markerBytes)
	if startIdx < 0 || endIdx <= startIdx {
		se := bytes.TrimSpace(stderrBuf.Bytes())
		if len(se) > 300 {
			se = se[:300]
		}
		markerErr := errors.New("loginenv: marker not found in shell output")
		if len(se) > 0 {
			return nil, &loginEnvError{err: markerErr, stderr: string(se)}
		}
		return nil, markerErr
	}

	payload := out[startIdx+len(markerBytes) : endIdx]
	entries := bytes.Split(payload, []byte{0})

	envMap := make(map[string]string)
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		eq := bytes.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		key := string(entry[:eq])
		val := string(entry[eq+1:])
		if key == "" || excludedKeys[key] {
			continue
		}
		envMap[key] = val
	}

	// 对 PATH 进行 augmentedPath 扩充（见 augmentedPath）
	envMap["PATH"] = augmentedPath(envMap["PATH"])
	if envMap["LANG"] == "" {
		envMap["LANG"] = "en_US.UTF-8"
	}
	addSystemProxy(envMap)

	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, k+"="+v)
	}
	return result, nil
}

// fallbackEnvironment 的规则：
// 1. 获取当前进程 os.Environ()；
// 2. 剔除 excludedKeys；
// 3. 对 PATH 进行 augmentedPath 扩充；
// 4. 若无 LANG 则设置 en_US.UTF-8。
func fallbackEnvironment() []string {
	envMap := make(map[string]string)
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		val := kv[eq+1:]
		if excludedKeys[key] {
			continue
		}
		envMap[key] = val
	}

	envMap["PATH"] = augmentedPath(envMap["PATH"])
	if envMap["LANG"] == "" {
		envMap["LANG"] = "en_US.UTF-8"
	}
	addSystemProxy(envMap)

	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, k+"="+v)
	}
	return result
}

// addSystemProxy 把系统代理补进环境，
// 只写环境里还没有的 key，用户 shell 自己设置的代理优先。
func addSystemProxy(envMap map[string]string) {
	for key, value := range systemProxyFunc() {
		if _, exists := envMap[key]; !exists {
			envMap[key] = value
		}
	}
}

// augmentedPath 的规则：
// 1. 保留原有 entries 及其相对顺序；
// 2. Windows 追加注册表里最新的用户 PATH（进程环境在启动时就固定了）；
// 3. 预置平台相关的 common 目录；若原列表中未包含，则追加至末尾；
// 4. 用平台的路径列表分隔符（os.PathListSeparator）重新拼接。
func augmentedPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}

	var entries []string
	seen := make(map[string]bool)
	add := func(entry string) {
		if entry == "" {
			return
		}
		key := pathKey(entry)
		if seen[key] {
			return
		}
		seen[key] = true
		entries = append(entries, entry)
	}
	for _, part := range filepath.SplitList(path) {
		add(part)
	}
	for _, part := range filepath.SplitList(userPathFunc()) {
		add(part)
	}
	for _, dir := range commonPathDirs(home) {
		add(dir)
	}

	return strings.Join(entries, string(os.PathListSeparator))
}

// pathKey 把 PATH 条目归一化成去重用的键：Windows 路径大小写不敏感。
func pathKey(entry string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(entry)
	}
	return entry
}

// commonPathDirs 返回值得预置进 PATH 的常见安装目录，按平台区分。
func commonPathDirs(home string) []string {
	if runtime.GOOS == "windows" {
		return windowsCommonPathDirs(home)
	}
	return []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/usr/local/bin",
		filepath.Join(home, ".local/bin"),
		filepath.Join(home, ".bun/bin"),
		filepath.Join(home, ".cargo/bin"),
		filepath.Join(home, ".npm-global/bin"),
		filepath.Join(home, ".volta/bin"),
		filepath.Join(home, ".version-fox/sdks/nodejs/bin"),
		filepath.Join(home, ".version-fox/shims"),
		filepath.Join(home, ".local/share/mise/shims"),
		filepath.Join(home, ".asdf/shims"),
		"/usr/bin",
		"/bin",
		"/usr/sbin",
		"/sbin",
	}
}

// windowsCommonPathDirs 覆盖 npm 全局 bin、WindowsApps、Program Files\nodejs 等目录。
func windowsCommonPathDirs(home string) []string {
	var dirs []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		dirs = append(dirs, filepath.Join(appData, "npm"))
	}
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		dirs = append(dirs,
			filepath.Join(localAppData, "Programs"),
			filepath.Join(localAppData, "Microsoft", "WindowsApps"),
			// agy 的官方安装脚本默认装到 %LOCALAPPDATA%\agy\bin。
			filepath.Join(localAppData, "agy", "bin"),
		)
	}
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		dirs = append(dirs, filepath.Join(programFiles, "nodejs"))
	}
	if home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".bun", "bin"),
			filepath.Join(home, ".cargo", "bin"),
			filepath.Join(home, ".volta", "bin"),
		)
	}
	return dirs
}

// isExecutable 检查文件是否存在、不是目录且具有可执行权限。
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		// Windows 没有 Unix 的执行权限位，存在且不是目录即视为可执行。
		return true
	}
	// 在 Unix 系统上校验执行权限位
	return info.Mode().Perm()&0111 != 0
}
