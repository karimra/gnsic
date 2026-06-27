package store

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/karimra/gnsic/server/certz/profile"
)

type mapStore struct {
	config   StoreConfig
	mu       sync.Mutex
	profiles map[profile.ProfileID]*profile.CertzProfile
	watchers map[profile.ProfileID]map[string]chan *profile.CertzProfile
}

func NewMap(config StoreConfig) Store {
	return &mapStore{
		config:   config,
		profiles: make(map[profile.ProfileID]*profile.CertzProfile),
		watchers: make(map[profile.ProfileID]map[string]chan *profile.CertzProfile),
	}
}

func (s *mapStore) Get(id profile.ProfileID) (*profile.CertzProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	czp, ok := s.profiles[id]
	if !ok {
		return nil, ErrNotFound
	}
	return profile.Copy(czp), nil
}

func (s *mapStore) Set(id profile.ProfileID, czp *profile.CertzProfile) error {
	if czp == nil {
		return errors.New("certz profile is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	initProfile := !czp.HasMaterial()
	old, ok := s.profiles[id]
	if !ok {
		if s.config.MaxProfiles > 0 && len(s.profiles) >= s.config.MaxProfiles {
			return errors.New("max profiles reached")
		}
		s.profiles[id] = profile.Copy(czp)
	} else if !initProfile {
		s.profiles[id] = profile.Copy(czp)
	} else {
		czp = old
	}
	if initProfile {
		return nil
	}
	stored := s.profiles[id]
	notify(s.watchers[id], stored)
	return nil
}

func (s *mapStore) Delete(id profile.ProfileID) error {
	if id == profile.DefaultProfileName {
		return errors.New("cannot delete default profile")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.profiles[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.profiles, id)
	notify(s.watchers[id], &profile.CertzProfile{})
	return nil
}

func (s *mapStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.profiles))
	for id := range s.profiles {
		ids = append(ids, string(id))
	}
	return ids, nil
}

type watcher struct {
	id string
	ch chan *profile.CertzProfile
}

func (s *mapStore) Watch(id profile.ProfileID) (<-chan *profile.CertzProfile, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		s.mu.Lock()
		delete(s.watchers[id], w.id)
		if len(s.watchers[id]) == 0 {
			delete(s.watchers, id)
		}
		s.mu.Unlock()
	}, nil
}

func (s *mapStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil
}
