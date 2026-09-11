// Portcast-bootstrap is the static trust entry for the canonical service.
// It runs inside systemd RootDirectory before CPython or a dynamic loader.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var heldDeploymentLock *os.File

const (
	appRoot       = "/app"
	anchorPath    = "/etc/cptc-harness/trust/portcast-live-v1.sha256"
	releasePath   = "/app/cptc_harness/resources/release-integrity.json"
	bootstrapPath = "/app/cptc_harness/resources/portcast-bootstrap-v1.sha256"
	launcherPath  = "/app/deployment/portcast-bootstrap"
	runtimeRoot   = "/app/vendor/portcast-rootfs-runtime"
	loaderPath    = runtimeRoot + "/lib/ld-linux-x86-64.so.2"
	pythonPath    = runtimeRoot + "/bin/python3.14"
	lockPath      = "/var/lib/cptc-harness/portcast-live-v1/deployment.lock"
)

func fail() { os.Exit(126) }

func trustedOpen(path string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, errors.New("invalid absolute path")
	}
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := root
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			syscall.Close(current)
			return nil, errors.New("invalid component")
		}
		last := index == len(parts)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last || directory {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(current, part, flags, 0)
		syscall.Close(current)
		if openErr != nil {
			return nil, openErr
		}
		var info syscall.Stat_t
		if err = syscall.Fstat(next, &info); err != nil {
			syscall.Close(next)
			return nil, err
		}
		kindOK := info.Mode&syscall.S_IFMT == syscall.S_IFREG
		if !last || directory {
			kindOK = info.Mode&syscall.S_IFMT == syscall.S_IFDIR
		}
		if !kindOK || info.Uid != 0 || info.Mode&0022 != 0 {
			syscall.Close(next)
			return nil, errors.New("untrusted metadata")
		}
		current = next
	}
	return os.NewFile(uintptr(current), path), nil
}

func digestFile(path string) (string, error) {
	file, err := trustedOpen(path, false)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, 128*1024*1024+1)); err != nil {
		return "", err
	}
	if info, statErr := file.Stat(); statErr != nil || info.Size() > 128*1024*1024 {
		return "", errors.New("file exceeds limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readTrusted(path string, maximum int64) ([]byte, error) {
	file, err := trustedOpen(path, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("file exceeds limit")
	}
	return value, nil
}

func parseAnchor(raw []byte) (map[string]string, error) {
	if strings.ContainsRune(string(raw), 0) {
		return nil, errors.New("NUL")
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 5 || lines[0] != "PORTCAST-TRUST-V2" || lines[4] != "" {
		return nil, errors.New("anchor grammar")
	}
	result := map[string]string{}
	for index, key := range []string{"release", "bootstrap", "launcher"} {
		prefix := key + " "
		if !strings.HasPrefix(lines[index+1], prefix) {
			return nil, errors.New("anchor field")
		}
		value := strings.TrimPrefix(lines[index+1], prefix)
		if len(value) != 64 {
			return nil, errors.New("anchor digest")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func parseBootstrap(raw []byte) (map[string]string, error) {
	if strings.ContainsRune(string(raw), 0) {
		return nil, errors.New("NUL")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	if !scanner.Scan() || scanner.Text() != "PORTCAST-BOOTSTRAP-V1" {
		return nil, errors.New("bootstrap grammar")
	}
	result := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			return nil, errors.New("blank entry")
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return nil, errors.New("bootstrap entry")
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return nil, err
		}
		relative := parts[1]
		if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || strings.ContainsAny(relative, "\x00\r\n\t") {
			return nil, errors.New("bootstrap path")
		}
		if _, exists := result[relative]; exists {
			return nil, errors.New("duplicate path")
		}
		result[relative] = parts[0]
	}
	if err := scanner.Err(); err != nil || len(result) == 0 {
		return nil, errors.New("bootstrap read")
	}
	return result, nil
}

func verifyTree(expected map[string]string) error {
	actual := map[string]bool{}
	err := filepath.WalkDir(appRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("untrusted tree metadata")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("nonregular tree entry")
		}
		if info.Sys().(*syscall.Stat_t).Nlink != 1 {
			return errors.New("hard-linked tree entry")
		}
		relative, _ := filepath.Rel(appRoot, path)
		if relative == "deployment/portcast-bootstrap" || relative == "cptc_harness/resources/release-integrity.json" || relative == "cptc_harness/resources/portcast-bootstrap-v1.sha256" {
			return nil
		}
		digest, ok := expected[relative]
		if !ok {
			return fmt.Errorf("unlisted file: %s", relative)
		}
		actual[relative] = true
		value, err := digestFile(path)
		if err != nil || value != digest {
			return errors.New("tree hash differs")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("missing tree entry")
	}
	return nil
}

func verify() error {
	raw, err := readTrusted(anchorPath, 1024)
	if err != nil {
		return err
	}
	anchor, err := parseAnchor(raw)
	if err != nil {
		return err
	}
	for name, path := range map[string]string{"release": releasePath, "bootstrap": bootstrapPath, "launcher": launcherPath} {
		value, err := digestFile(path)
		if err != nil || value != anchor[name] {
			return errors.New("anchor mismatch")
		}
	}
	list, err := readTrusted(bootstrapPath, 1024*1024)
	if err != nil {
		return err
	}
	expected, err := parseBootstrap(list)
	if err != nil {
		return err
	}
	return verifyTree(expected)
}

func pythonArgs(script string, extra ...string) []string {
	args := []string{loaderPath, "--inhibit-cache", "--library-path", runtimeRoot + "/lib", pythonPath, "-I", "-S", "-B", script}
	return append(args, extra...)
}

func retainDeploymentLock() error {
	file, err := trustedOpen(lockPath, false)
	if err != nil {
		return err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		file.Close()
		return err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_SETFD, 0); errno != 0 {
		file.Close()
		return errno
	}
	runtime.SetFinalizer(file, nil)
	heldDeploymentLock = file
	return nil // Intentionally retained across exec for the complete service lifetime.
}

func releaseDeploymentLock() error {
	if heldDeploymentLock != nil {
		err := heldDeploymentLock.Close()
		heldDeploymentLock = nil
		return err
	}
	return nil
}

func validAcceptanceRunID(value string) bool {
	if len(value) != len("accept-20060102T150405Z-0123abcd") || !strings.HasPrefix(value, "accept-") {
		return false
	}
	for index, character := range value {
		switch {
		case index < 7:
			// Prefix was checked as one exact string above.
		case index == 15:
			if character != 'T' {
				return false
			}
		case index == 22:
			if character != 'Z' {
				return false
			}
		case index == 23:
			if character != '-' {
				return false
			}
		case index > 23:
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return false
			}
		default:
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func main() {
	if err := retainDeploymentLock(); err != nil {
		fail()
	}
	if err := verify(); err != nil {
		fail()
	}
	arguments := os.Args[1:]
	if len(arguments) == 0 {
		if syscall.Exec(loaderPath, pythonArgs("/app/testing/cptc11_lab/portcast_service.py"), []string{}) != nil {
			fail()
		}
	}
	if len(arguments) == 1 && (arguments[0] == "--broker-worker" || arguments[0] == "--verify-startup-only") {
		if arguments[0] == "--broker-worker" {
			bwrap := runtimeRoot + "/bin/bwrap"
			ledger := "/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation"
			bwrapArgs := []string{loaderPath, "--inhibit-cache", "--library-path", runtimeRoot + "/lib", bwrap,
				"--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--share-net",
				"--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
				"--ro-bind", "/app", "/app", "--dir", "/etc", "--dir", "/etc/cptc-harness", "--dir", "/etc/cptc-harness/trust",
				"--ro-bind", anchorPath, anchorPath, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
				"--dir", "/var", "--dir", "/var/lib", "--dir", "/var/lib/cptc-harness",
				"--dir", "/var/lib/cptc-harness/portcast-live-v1", "--dir", "/var/lib/cptc-harness/portcast-live-v1/runtime", "--dir", "/var/lib/cptc-harness/portcast-live-v1/runtime/ledger",
				"--ro-bind", ledger, ledger, "--chdir", ledger,
			}
			bwrapArgs = append(bwrapArgs, pythonArgs("/app/testing/cptc11_lab/portcast_service.py", "--broker-worker")...)
			if releaseDeploymentLock() != nil {
				fail()
			}
			if syscall.Exec(loaderPath, bwrapArgs, []string{}) != nil {
				fail()
			}
		}
		if syscall.Exec(loaderPath, pythonArgs("/app/testing/cptc11_lab/portcast_service.py", arguments[0]), []string{}) != nil {
			fail()
		}
	}
	if len(arguments) == 2 && arguments[0] == "--audit-worker" {
		fd, err := strconv.Atoi(arguments[1])
		if err != nil || fd < 3 || fd > 63 {
			fail()
		}
		bwrap := runtimeRoot + "/bin/bwrap"
		bwrapArgs := []string{loaderPath, "--inhibit-cache", "--library-path", runtimeRoot + "/lib", bwrap,
			"--unshare-user", "--uid", "0", "--gid", "0", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
			"--die-with-parent", "--cap-drop", "ALL", "--clearenv",
			"--ro-bind", "/app", "/app", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
			"--bind", "/var/lib/cptc-harness/portcast-live-v1/runtime/audit", "/audit",
			"--ro-bind-data", strconv.Itoa(fd), "/config.json",
		}
		bwrapArgs = append(bwrapArgs, pythonArgs("/app/cptc_harness/audit_worker.py")...)
		if releaseDeploymentLock() != nil {
			fail()
		}
		if syscall.Exec(loaderPath, bwrapArgs, []string{}) != nil {
			fail()
		}
	}
	if len(arguments) == 2 && arguments[0] == "--acceptance-audit" && validAcceptanceRunID(arguments[1]) {
		if syscall.Exec(loaderPath, pythonArgs("/app/testing/cptc11_lab/portcast_service.py", arguments...), []string{}) != nil {
			fail()
		}
	}
	fail()
}
