package browserenv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestProfilePersistsIdentityAndExcludesConcurrentWriters(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	p, err := Open(t.Context(), root, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(p.Directory, "retained-storage"), []byte("saved"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if second, err := Open(ctx, root, e); err == nil {
		second.Close()
		t.Fatal("same profile admitted two writers")
	}
	other, _ := New()
	independent, err := Open(t.Context(), root, other)
	if err != nil {
		t.Fatal(err)
	}
	independent.Close()
	p.Close()
	// A different container hostname can leave these symlinks after a crash.
	if err = os.Symlink("old-container-999999", filepath.Join(p.Directory, "SingletonLock")); err != nil {
		t.Fatal(err)
	}
	returned, err := Open(t.Context(), root, e)
	if err != nil {
		t.Fatal(err)
	}
	defer returned.Close()
	data, err := os.ReadFile(filepath.Join(returned.Directory, "retained-storage"))
	if err != nil || string(data) != "saved" {
		t.Fatal("restart destroyed browser storage", err)
	}
	recipe, err := os.ReadFile(returned.RecipePath)
	if err != nil || !reflect.DeepEqual(recipe, []byte(e.Recipe)) {
		t.Fatal("return changed fixed recipe", err)
	}
	info, _ := os.Stat(returned.Directory)
	if info.Mode().Perm() != 0700 {
		t.Fatal("profile is not private")
	}
}

func TestProfileRecoveryKillsOnlyItsOrphanChildren(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process recovery inspects Linux /proc; run in Linux CI")
	}
	e, _ := New()
	other, _ := New()
	owned := exec.Command("sleep", "60")
	owned.Env = append(os.Environ(), processMarker+e.ProfileID.String())
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	defer owned.Process.Kill()
	unrelated := exec.Command("sleep", "60")
	unrelated.Env = append(os.Environ(), processMarker+other.ProfileID.String())
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { unrelated.Process.Kill(); unrelated.Wait() }()
	p, err := Open(t.Context(), t.TempDir(), e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = owned.Wait(); err == nil {
		t.Fatal("orphan survived recovery")
	}
	if err = unrelated.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		t.Fatal("recovery killed another profile", err)
	}
}

func TestMissingAndChangedEnvironmentFailClosed(t *testing.T) {
	if (Environment{}).Validate() == nil {
		t.Fatal("anonymous environment accepted")
	}
	e, _ := New()
	e.RecipeVersion = "future-engine"
	if e.Validate() == nil {
		t.Fatal("uncontrolled engine upgrade accepted")
	}
	e.RecipeVersion = Version
	e.Recipe = []byte(`{"name":"altered"}`)
	if e.Validate() == nil {
		t.Fatal("altered recipe accepted")
	}
}
