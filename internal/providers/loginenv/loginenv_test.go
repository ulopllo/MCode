package loginenv

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetState(t *testing.T) {
	// 先拿 loadMu，等可能在跑的登录环境加载退出，避免和后台 goroutine 同时写缓存。
	loadMu.Lock()
	defer loadMu.Unlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	loaded = false
	loading = false
	loadFailed = false
	lastAttempt = time.Time{}
	cachedEnv = nil
	cachedPath = ""
	loadFunc = nil
}

func TestAugmentedPath(t *testing.T) {
	customDir := "/custom/bin"
	res := augmentedPath(customDir)

	if !strings.HasPrefix(res, customDir) {
		t.Fatalf("expected augmented PATH to start with custom dir %q, got: %s", customDir, res)
	}

	// 确认包含常用 common 目录
	commonDirs := []string{
		"/opt/homebrew/bin",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
	}
	for _, dir := range commonDirs {
		if !strings.Contains(res, dir) {
			t.Errorf("expected PATH to contain %q, but got: %s", dir, res)
		}
	}

	// 再次传入已包含 common 目录的路径，验证不会发生重复追加
	res2 := augmentedPath(res)
	parts := strings.Split(res2, ":")
	seen := make(map[string]int)
	for _, p := range parts {
		seen[p]++
		if seen[p] > 1 {
			t.Errorf("found duplicate directory %q in augmented PATH: %s", p, res2)
		}
	}
}

// Windows 的进程 PATH 在启动后不会再变，注册表里的用户 PATH 才是最新值；
// 合并后还要避免同一个目录出现两次。
func TestAugmentedPathMergesUserPath(t *testing.T) {
	original := userPathFunc
	t.Cleanup(func() { userPathFunc = original })

	userDir := filepath.Join(t.TempDir(), "agy", "bin")
	userPathFunc = func() string { return userDir }

	res := augmentedPath("")
	if !strings.Contains(strings.ToLower(res), strings.ToLower(userDir)) {
		t.Fatalf("expected PATH to contain user dir %q, got: %s", userDir, res)
	}

	res2 := augmentedPath(res)
	if got := strings.Count(strings.ToLower(res2), strings.ToLower(userDir)); got != 1 {
		t.Fatalf("user dir appears %d times in augmented PATH: %s", got, res2)
	}
}

// agy 的 Windows 安装脚本默认装到 %LOCALAPPDATA%\agy\bin，必须作为常见目录补进 PATH。
func TestWindowsCommonPathDirsIncludesAgy(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	localAppData := filepath.Join(t.TempDir(), "Local")
	t.Setenv("LOCALAPPDATA", localAppData)

	want := filepath.Join(localAppData, "agy", "bin")
	for _, dir := range windowsCommonPathDirs(t.TempDir()) {
		if dir == want {
			return
		}
	}
	t.Fatalf("windowsCommonPathDirs 缺少 %q", want)
}

func TestFallbackEnvironment(t *testing.T) {
	resetState(t)
	defer resetState(t)

	// 模拟 loadFunc 失败
	loadFunc = func() ([]string, error) {
		return nil, errors.New("simulated shell spawn failure")
	}

	env := Environ()
	if len(env) == 0 {
		t.Fatal("expected non-empty environment from fallback")
	}

	envMap := make(map[string]string)
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			envMap[kv[:eq]] = kv[eq+1:]
		}
	}

	// 验证 excludedKeys 已被排除
	for key := range excludedKeys {
		if _, exists := envMap[key]; exists {
			t.Errorf("expected excluded key %q to be filtered out", key)
		}
	}

	// 验证 LANG 和 PATH 存在且被扩充
	if envMap["LANG"] == "" {
		t.Error("expected LANG to be set in fallback environment")
	}
	if !strings.Contains(PATH(), "/usr/bin") {
		t.Errorf("expected PATH to contain /usr/bin, got: %s", PATH())
	}
}

func TestFallbackEnvironmentKeepsUserProxy(t *testing.T) {
	resetState(t)
	defer resetState(t)

	original := systemProxyFunc
	t.Cleanup(func() { systemProxyFunc = original })
	systemProxyFunc = func() map[string]string {
		return map[string]string{
			"HTTPS_PROXY": "http://sys:1",
			"HTTP_PROXY":  "http://sys:1",
		}
	}
	t.Setenv("HTTPS_PROXY", "http://user:2")

	// 保证 HTTP_PROXY 不存在，才能验证系统代理会被补入
	staleHTTPProxy, hadHTTPProxy := os.LookupEnv("HTTP_PROXY")
	os.Unsetenv("HTTP_PROXY")
	t.Cleanup(func() {
		if hadHTTPProxy {
			os.Setenv("HTTP_PROXY", staleHTTPProxy)
		}
	})

	envMap := make(map[string]string)
	for _, kv := range fallbackEnvironment() {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			envMap[kv[:eq]] = kv[eq+1:]
		}
	}

	if envMap["HTTPS_PROXY"] != "http://user:2" {
		t.Errorf("HTTPS_PROXY = %q，期望用户 shell 自己的设置优先（http://user:2）", envMap["HTTPS_PROXY"])
	}
	if envMap["HTTP_PROXY"] != "http://sys:1" {
		t.Errorf("HTTP_PROXY = %q，期望系统代理 http://sys:1", envMap["HTTP_PROXY"])
	}
}

func TestFindBinary(t *testing.T) {
	resetState(t)
	defer resetState(t)

	binDir := t.TempDir()
	fallbackDir := t.TempDir()
	onPath := filepath.Join(binDir, "mcode-find-test")
	if err := os.WriteFile(onPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	inFallback := filepath.Join(fallbackDir, "mcode-find-fallback")
	if err := os.WriteFile(inFallback, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	nonExec := filepath.Join(fallbackDir, "mcode-find-nonexec")
	if err := os.WriteFile(nonExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	loadFunc = func() ([]string, error) {
		return []string{"PATH=" + binDir}, nil
	}

	// 1. 登录 shell 的 PATH 优先
	path, ok := FindBinary([]string{"mcode-find-test"}, []string{fallbackDir})
	if !ok || path != onPath {
		t.Fatalf("FindBinary = %q, %v，期望 %q, true", path, ok, onPath)
	}

	// 2. PATH 里没有时回退到常见安装目录
	path, ok = FindBinary([]string{"mcode-find-fallback"}, []string{fallbackDir})
	if !ok || path != inFallback {
		t.Fatalf("FindBinary 回退 = %q, %v，期望 %q, true", path, ok, inFallback)
	}

	// 3. 候选名按顺序尝试（command-code/commandcode/cmd 这类别名）
	path, ok = FindBinary([]string{"mcode-find-missing", "mcode-find-test"}, nil)
	if !ok || path != onPath {
		t.Fatalf("FindBinary 别名 = %q, %v，期望 %q, true", path, ok, onPath)
	}

	// 4. 都找不到时返回 false
	if _, ok := FindBinary([]string{"mcode-find-missing"}, []string{fallbackDir}); ok {
		t.Fatal("不存在的可执行文件不应算找到")
	}

	// 5. 无执行权限的文件不算可执行文件
	if _, ok := FindBinary([]string{"mcode-find-nonexec"}, []string{fallbackDir}); ok {
		t.Fatal("无执行权限的文件不应算找到")
	}
}

func TestProbePath(t *testing.T) {
	resetState(t)
	defer resetState(t)

	loadFunc = func() ([]string, error) {
		time.Sleep(200 * time.Millisecond)
		return []string{"PATH=" + os.Getenv("PATH")}, nil
	}

	// 显式路径不需要登录环境，结论立即确定。
	if found, decided := ProbePath("/bin/sh"); !found || !decided {
		t.Fatalf("显式路径应立刻确定: found=%v decided=%v", found, decided)
	}
	// 登录环境还在后台加载：没找到的名字不能当作最终结论。
	if _, decided := ProbePath("non_existent_binary_xyz_123"); decided {
		t.Fatal("登录环境未就绪时不应给出最终结论")
	}

	deadline := time.Now().Add(2 * time.Second)
	for !LoginEnvReady() {
		if time.Now().After(deadline) {
			t.Fatal("等待登录环境加载超时")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, decided := ProbePath("non_existent_binary_xyz_123"); !decided {
		t.Fatal("登录环境就绪后应给出最终结论")
	}
}

func TestLookPath(t *testing.T) {
	resetState(t)
	defer resetState(t)

	// 1. 查找已知存在的命令（如 sh）
	shPath, err := LookPath("sh")
	if err != nil {
		t.Fatalf("expected LookPath(\"sh\") to succeed, got: %v", err)
	}
	if !filepath.IsAbs(shPath) {
		t.Errorf("expected absolute path for sh, got: %s", shPath)
	}

	// 2. 绝对路径检查
	absSh, err := LookPath(shPath)
	if err != nil {
		t.Fatalf("expected LookPath(%q) to succeed, got: %v", shPath, err)
	}
	if absSh != shPath {
		t.Errorf("expected %q, got: %s", shPath, absSh)
	}

	// 3. 不存在的命令返回 ErrNotFound
	_, err = LookPath("non_existent_binary_xyz_123")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected exec.ErrNotFound, got: %v", err)
	}

	// 4. 不存在的绝对路径返回 ErrNotFound
	_, err = LookPath("/non/existent/path/xyz_123")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected exec.ErrNotFound for missing abs path, got: %v", err)
	}

	// 5. 目录非可执行文件
	tmpDir := t.TempDir()
	_, err = LookPath(tmpDir)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected exec.ErrNotFound for directory, got: %v", err)
	}

	// 6. 无执行权限的文件
	nonExecFile := filepath.Join(tmpDir, "some_file.txt")
	if err := os.WriteFile(nonExecFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LookPath(nonExecFile)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected exec.ErrNotFound for non-executable file, got: %v", err)
	}
}

func TestRetryAfterFailure(t *testing.T) {
	resetState(t)
	defer resetState(t)

	// 1. 首次 loadFunc 返回错误 → 拿到兜底 PATH 且 loadFailed 为 true
	loadFunc = func() ([]string, error) {
		return nil, errors.New("simulated initial shell spawn failure")
	}

	fallbackPath := PATH()
	if fallbackPath == "" {
		t.Fatal("expected non-empty PATH on fallback")
	}

	cacheMu.RLock()
	failed := loadFailed
	isLoaded := loaded
	cacheMu.RUnlock()

	if !isLoaded {
		t.Fatal("expected loaded to be true after initial attempt")
	}
	if !failed {
		t.Fatal("expected loadFailed to be true after initial failure")
	}

	// 2. 把 lastAttempt 拨到 31 秒前并让 loadFunc 返回成功后，
	// LookPath 会触发重新加载，并在新 PATH 里找到一个测试用临时可执行文件
	tmpDir := t.TempDir()
	binName := "mcode-retry-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	targetBin := filepath.Join(tmpDir, binName)
	if err := os.WriteFile(targetBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	loadFunc = func() ([]string, error) {
		return []string{
			"PATH=" + tmpDir + string(os.PathListSeparator) + fallbackPath,
			"USER=testuser",
		}, nil
	}

	cacheMu.Lock()
	lastAttempt = time.Now().Add(-31 * time.Second)
	cacheMu.Unlock()

	foundPath, err := LookPath(binName)
	if err != nil {
		t.Fatalf("expected LookPath to succeed after reload, got: %v", err)
	}
	if foundPath != targetBin {
		t.Fatalf("expected LookPath to return %q, got: %q", targetBin, foundPath)
	}

	cacheMu.RLock()
	failedAfterSuccess := loadFailed
	goodEnv := cachedEnv
	goodPath := cachedPath
	cacheMu.RUnlock()

	if failedAfterSuccess {
		t.Fatal("expected loadFailed to be false after successful reload")
	}
	if !strings.Contains(goodPath, tmpDir) {
		t.Fatalf("expected cachedPath to contain tmpDir %q, got: %s", tmpDir, goodPath)
	}

	// 3. 成功加载后再次失败不会覆盖已有的好缓存
	loadFunc = func() ([]string, error) {
		return nil, errors.New("simulated subsequent shell spawn failure")
	}

	cacheMu.Lock()
	lastAttempt = time.Now().Add(-31 * time.Second)
	cacheMu.Unlock()

	performLoad(true)

	cacheMu.RLock()
	afterFailureEnv := cachedEnv
	afterFailurePath := cachedPath
	cacheMu.RUnlock()

	if afterFailurePath != goodPath {
		t.Fatalf("expected good cachedPath %q to be preserved, got: %q", goodPath, afterFailurePath)
	}
	if len(afterFailureEnv) != len(goodEnv) {
		t.Fatalf("expected good cachedEnv to be preserved (len %d), got len %d", len(goodEnv), len(afterFailureEnv))
	}

	// 确认在好缓存保留的情况下 LookPath 仍能正常查找到该文件
	if p, err := LookPath(binName); err != nil || p != targetBin {
		t.Fatalf("expected LookPath to still find %q after subsequent failure, got: %q, %v", targetBin, p, err)
	}
}

func TestLookPathRetryNoDuplicateLoad(t *testing.T) {
	resetState(t)
	defer resetState(t)

	// 1. 模拟首次加载失败
	loadFunc = func() ([]string, error) {
		return nil, errors.New("simulated initial shell spawn failure")
	}
	fallbackPath := PATH()

	tmpDir := t.TempDir()
	binName := "mcode-concurrent-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	targetBin := filepath.Join(tmpDir, binName)
	if err := os.WriteFile(targetBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var loadCount int64
	loadFunc = func() ([]string, error) {
		atomic.AddInt64(&loadCount, 1)
		time.Sleep(30 * time.Millisecond)
		return []string{
			"PATH=" + tmpDir + string(os.PathListSeparator) + fallbackPath,
			"USER=testuser",
		}, nil
	}

	cacheMu.Lock()
	lastAttempt = time.Now().Add(-31 * time.Second)
	cacheMu.Unlock()

	// 并发触发 LookPath，验证只会触发一次加载
	var wg sync.WaitGroup
	const goroutines = 5
	errs := make([]error, goroutines)
	paths := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			paths[idx], errs[idx] = LookPath(binName)
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if paths[i] != targetBin {
			t.Fatalf("goroutine %d got %q, want %q", i, paths[i], targetBin)
		}
	}

	if count := atomic.LoadInt64(&loadCount); count != 1 {
		t.Fatalf("expected exactly 1 load call, got %d", count)
	}

	// 刚完成加载后，在 retryInterval 内再次查找不存在的命令，不应重复触发子进程加载
	_, err := LookPath("non_existent_command_xyz")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
	if count := atomic.LoadInt64(&loadCount); count != 1 {
		t.Fatalf("expected loadCount to remain 1, got %d", count)
	}
}
