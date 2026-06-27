package store

import (
	"errors"

	"github.com/karimra/gnsic/server/certz/profile"
)

const (
	profileFileName = "profile.json"
)

var (
	ErrNotFound = errors.New("not found")
)

type Store interface {
	Get(id profile.ProfileID) (*profile.CertzProfile, error)
	Set(id profile.ProfileID, czp *profile.CertzProfile) error
	Delete(id profile.ProfileID) error
	List() ([]string, error)
	Watch(profile.ProfileID) (<-chan *profile.CertzProfile, func(), error)
	Close() error
}

type StoreConfig struct {
	MaxWatchers int
	MaxProfiles int
	Dir         string
	Logging     *Logging
}

type Logging struct {
	File  string
	Debug bool
}

func countWatchers(watchers map[profile.ProfileID]map[string]chan *profile.CertzProfile) int {
	total := 0
	for _, m := range watchers {
		total += len(m)
	}
	return total
}

func notify(watchers map[string]chan *profile.CertzProfile, czp *profile.CertzProfile) {
	for _, ch := range watchers {
		select {
		case ch <- profile.Copy(czp):
		default:
			// Buffer full: drop the stale pending value, then deliver the latest.
			// All sends happen under the store lock, so only this goroutine writes
			// to ch; after draining there is guaranteed room for the new value.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- profile.Copy(czp):
			default:
			}
		}
	}
}
