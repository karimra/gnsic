package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karimra/gnsic/server/certz/profile"
)

func material() *profile.CertzProfile {
	return &profile.CertzProfile{
		CertPEM: []byte("cert"),
		KeyPEM:  []byte("key"),
	}
}

func recvWithin(t *testing.T, ch <-chan *profile.CertzProfile, d time.Duration) (*profile.CertzProfile, bool) {
	t.Helper()
	select {
	case p := <-ch:
		return p, true
	case <-time.After(d):
		return nil, false
	}
}

func TestMapSetGetDelete(t *testing.T) {
	s := NewMap(StoreConfig{})
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Get("missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.CertPEM) != "cert" || string(got.KeyPEM) != "key" {
		t.Fatalf("unexpected profile: %+v", got)
	}
	if err := s.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("p1"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMapWatchNotifiesOnMaterial(t *testing.T) {
	s := NewMap(StoreConfig{})
	t.Cleanup(func() { _ = s.Close() })

	ch, cancel, err := s.Watch("p1")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer cancel()

	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p, ok := recvWithin(t, ch, time.Second)
	if !ok {
		t.Fatal("expected a watcher notification")
	}
	if !p.HasMaterial() {
		t.Fatalf("expected material in notification, got %+v", p)
	}
}

// Fix #7: registering an empty profile must not wake watchers.
func TestMapInitDoesNotNotify(t *testing.T) {
	s := NewMap(StoreConfig{})
	t.Cleanup(func() { _ = s.Close() })

	ch, cancel, err := s.Watch("p1")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer cancel()

	if err := s.Set("p1", &profile.CertzProfile{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok := recvWithin(t, ch, 200*time.Millisecond); ok {
		t.Fatal("did not expect a notification for empty-profile registration")
	}
}

// Fix #1: a slow/absent consumer must never block Set (no deadlock), and the
// watcher should still converge on the latest value.
func TestMapNotifyNonBlocking(t *testing.T) {
	s := NewMap(StoreConfig{})
	t.Cleanup(func() { _ = s.Close() })

	ch, cancel, err := s.Watch("p1")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			p := material()
			p.Serial = string(rune('A' + (i % 26)))
			if err := s.Set("p1", p); err != nil {
				t.Errorf("Set: %v", err)
				return
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Set blocked on a non-consuming watcher (deadlock)")
	}

	// the buffered channel should still hold the latest state.
	if _, ok := recvWithin(t, ch, time.Second); !ok {
		t.Fatal("expected latest value to be available on the watch channel")
	}
}

// Fix #6: MaxWatchers is enforced.
func TestMapMaxWatchers(t *testing.T) {
	s := NewMap(StoreConfig{MaxWatchers: 1})
	t.Cleanup(func() { _ = s.Close() })

	_, cancel, err := s.Watch("p1")
	if err != nil {
		t.Fatalf("first Watch: %v", err)
	}
	defer cancel()

	if _, _, err := s.Watch("p2"); err == nil {
		t.Fatal("expected error when exceeding MaxWatchers")
	}
}

// Fix #6: MaxProfiles is enforced.
func TestMapMaxProfiles(t *testing.T) {
	s := NewMap(StoreConfig{MaxProfiles: 1})
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set p1: %v", err)
	}
	if err := s.Set("p2", material()); err == nil {
		t.Fatal("expected error when exceeding MaxProfiles")
	}
}

func TestMapDeleteDefaultBlocked(t *testing.T) {
	s := NewMap(StoreConfig{})
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Set(profile.DefaultProfileName, material()); err != nil {
		t.Fatalf("Set default: %v", err)
	}
	if err := s.Delete(profile.DefaultProfileName); err == nil {
		t.Fatal("expected error deleting default profile")
	}
}

func TestFSSetGetListDelete(t *testing.T) {
	dir := t.TempDir()
	s := NewFS(StoreConfig{Dir: dir})
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.HasMaterial() {
		t.Fatalf("expected material, got %+v", got)
	}

	ids, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0] != "p1" {
		t.Fatalf("unexpected list: %v", ids)
	}

	if err := s.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("p1"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// Fix #4: profile material on disk must be owner-only.
func TestFSPermissions(t *testing.T) {
	dir := t.TempDir()
	s := NewFS(StoreConfig{Dir: dir})
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	dirInfo, err := os.Stat(filepath.Join(dir, "p1"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("profile dir perm = %o, want 700", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, "p1", profileFileName))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("profile file perm = %o, want 600", perm)
	}
}

// Fix #6: MaxProfiles is enforced by the filesystem store too.
func TestFSMaxProfiles(t *testing.T) {
	dir := t.TempDir()
	s := NewFS(StoreConfig{Dir: dir, MaxProfiles: 1})
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Set("p1", material()); err != nil {
		t.Fatalf("Set p1: %v", err)
	}
	if err := s.Set("p2", material()); err == nil {
		t.Fatal("expected error when exceeding MaxProfiles")
	}
}
