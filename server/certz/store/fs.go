package store

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/karimra/gnsic/server/certz/profile"
)

type fileStore struct {
	config StoreConfig
	cfn    context.CancelFunc
	logger *slog.Logger

	mw       sync.Mutex
	watchers map[profile.ProfileID]map[string]chan *profile.CertzProfile
}

func NewFS(config StoreConfig) Store {
	fsCert := &fileStore{
		config:   config,
		logger:   slog.New(slog.NewTextHandler(os.Stdout, nil)),
		watchers: make(map[profile.ProfileID]map[string]chan *profile.CertzProfile),
	}
	ctx, cfn := context.WithCancel(context.Background())
	fsCert.cfn = cfn
	go fsCert.Start(ctx)
	return fsCert
}

func (s *fileStore) Start(ctx context.Context) error {
	if err := os.MkdirAll(s.config.Dir, 0700); err != nil {
		return err
	}
	// watch the root directory plus every existing profile sub-directory so we
	// observe material files being written/removed out of band.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(s.config.Dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.config.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := watcher.Add(filepath.Join(s.config.Dir, e.Name())); err != nil {
			s.logger.Warn("failed to watch profile directory", "dir", e.Name(), "error", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return errors.New("watcher closed")
			}
			s.handleFSEvent(watcher, event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return errors.New("watcher closed")
			}
			s.logger.Warn("profile directory watcher error", "error", err)
		}
	}
}

// handleFSEvent reacts to out-of-band filesystem changes: it starts watching
// newly created profile directories and reloads/notifies watchers when a
// profile's material file is written, removed or renamed.
func (s *fileStore) handleFSEvent(watcher *fsnotify.Watcher, event fsnotify.Event) {
	s.logger.Debug("profile directory event", "event", event.String())

	// A new profile directory appeared: watch it for material changes.
	if event.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			if err := watcher.Add(event.Name); err != nil {
				s.logger.Warn("failed to watch new profile directory", "dir", event.Name, "error", err)
			}
			return
		}
	}

	// Only material files inside a profile directory are relevant.
	if filepath.Base(event.Name) != profileFileName {
		return
	}
	id := profile.ProfileID(filepath.Base(filepath.Dir(event.Name)))

	if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
		s.mw.Lock()
		notify(s.watchers[id], &profile.CertzProfile{})
		s.mw.Unlock()
		return
	}

	czp, err := s.Get(id)
	if err != nil {
		// The profile may have been removed concurrently; treat that as a
		// deletion rather than an error.
		if errors.Is(err, ErrNotFound) {
			czp = &profile.CertzProfile{}
		} else {
			s.logger.Warn("failed to reload profile after change", "profile", id, "error", err)
			return
		}
	}
	s.mw.Lock()
	notify(s.watchers[id], czp)
	s.mw.Unlock()
}

func (s *fileStore) Get(id profile.ProfileID) (*profile.CertzProfile, error) {
	profileDir := filepath.Join(s.config.Dir, string(id))
	info, err := os.Stat(profileDir)
	if err != nil {
		// if not found, return ErrNotFound
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("profile directory is not a directory")
	}
	materialFile := filepath.Join(profileDir, profileFileName)
	materialJSON, err := os.ReadFile(materialFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	czp := &profile.CertzProfile{}
	err = json.Unmarshal(materialJSON, czp)
	if err != nil {
		return nil, err
	}
	return profile.Copy(czp), nil
}

// RPC
func (s *fileStore) Set(id profile.ProfileID, czp *profile.CertzProfile) error {
	if czp == nil {
		return errors.New("certz profile is required")
	}
	profileDir := filepath.Join(s.config.Dir, string(id))
	profileFile := filepath.Join(profileDir, profileFileName)
	initProfile := !czp.HasMaterial()

	_, statErr := os.Stat(profileDir)
	isNew := os.IsNotExist(statErr)
	if statErr != nil && !isNew {
		return statErr
	}
	// enforce the configured profile cap on creation only.
	if isNew && s.config.MaxProfiles > 0 {
		ids, err := s.List()
		if err != nil {
			return err
		}
		if len(ids) >= s.config.MaxProfiles {
			return errors.New("max profiles reached")
		}
	}

	// directory holds private key material, keep it owner-only.
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return err
	}

	if initProfile {
		if _, err := os.Stat(profileFile); err == nil {
			existing := &profile.CertzProfile{}
			b, err := os.ReadFile(profileFile)
			if err != nil {
				return err
			}
			err = json.Unmarshal(b, existing)
			if err != nil {
				return err
			}
			if existing.HasMaterial() {
				return nil
			}
		}
	}

	specJSON, err := json.MarshalIndent(czp, "", "  ") // TODO: change to regular Marshal for JSON
	if err != nil {
		return err
	}

	// 0600: the file embeds the private key.
	if err := os.WriteFile(profileFile, specJSON, 0600); err != nil {
		return err
	}
	// registration of an empty profile should not wake watchers, mirroring mapStore.
	if initProfile {
		return nil
	}
	// notify the watchers
	s.mw.Lock()
	defer s.mw.Unlock()
	notify(s.watchers[id], czp)
	return nil
}

// RPC
func (s *fileStore) Delete(id profile.ProfileID) error {
	if id == profile.DefaultProfileName {
		return errors.New("cannot delete default profile")
	}
	profileDir := filepath.Join(s.config.Dir, string(id))
	_, err := os.Stat(profileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	err = os.RemoveAll(profileDir)
	if err != nil {
		return err
	}
	// notify the watchers
	s.mw.Lock()
	defer s.mw.Unlock()
	notify(s.watchers[id], &profile.CertzProfile{})
	return nil
}

// RPC
func (s *fileStore) List() ([]string, error) {
	profileDir := filepath.Join(s.config.Dir)
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		return nil, err
	}
	res := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			res = append(res, entry.Name())
		}
	}
	return res, nil
}

func (s *fileStore) Watch(id profile.ProfileID) (<-chan *profile.CertzProfile, func(), error) {
	s.mw.Lock()
	defer s.mw.Unlock()
	if s.config.MaxWatchers > 0 && countWatchers(s.watchers) >= s.config.MaxWatchers {
		return nil, nil, errors.New("max watchers reached")
	}
	w := &watcher{
		id: uuid.New().String(),
		ch: make(chan *profile.CertzProfile, 1),
	}
	if s.watchers[id] == nil {
		s.watchers[id] = make(map[string]chan *profile.CertzProfile)
	}
	s.watchers[id][w.id] = w.ch
	return w.ch, func() {
		close(w.ch)
		s.mw.Lock()
		delete(s.watchers[id], w.id)
		if len(s.watchers[id]) == 0 {
			delete(s.watchers, id)
		}
		s.mw.Unlock()
	}, nil

}

func (s *fileStore) Close() error {
	s.mw.Lock()
	defer s.mw.Unlock()
	if s.cfn != nil {
		s.cfn()
		s.cfn = nil
	}
	return nil
}
