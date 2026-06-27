package manager

import "github.com/karimra/gnsic/server/certz/profile"

func (m *Manager) GetProfile(id profile.ProfileID) (*profile.CertzProfile, error) {
	return m.store.Get(id)
}

func (m *Manager) ListProfiles() ([]string, error) {
	return m.store.List()
}

func (m *Manager) DeleteProfile(id profile.ProfileID) error {
	return m.store.Delete(id)
}

func (m *Manager) SetProfile(id profile.ProfileID, czp *profile.CertzProfile) error {
	return m.store.Set(id, czp)
}

func (m *Manager) WatchProfile(id profile.ProfileID) (<-chan *profile.CertzProfile, func(), error) {
	return m.store.Watch(id)
}
