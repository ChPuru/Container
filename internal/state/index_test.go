package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahuldhali/hull/internal/types"
)

func sampleNetwork(id, name string) *types.Network {
	return &types.Network{
		ID:         id,
		Name:       name,
		Driver:     "bridge",
		Scope:      "local",
		Created:    time.Unix(1700000000, 0).UTC(),
		BridgeName: "hull0",
		IPAM: types.IPAMConfig{
			Driver:  "default",
			Subnet:  "10.66.0.0/24",
			Gateway: "10.66.0.1",
		},
		Labels: map[string]string{"owner": "hull"},
	}
}

func TestNetworkRoundTrip(t *testing.T) {
	s := newTestStore(t)
	idA, idB := NewID(), NewID()

	if _, err := s.GetNetwork(idA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNetwork on empty index = %v, want ErrNotFound", err)
	}
	if list, err := s.ListNetworks(); err != nil || len(list) != 0 {
		t.Fatalf("ListNetworks on empty index = %v (%v)", list, err)
	}

	if err := s.PutNetwork(sampleNetwork(idA, "hullnet")); err != nil {
		t.Fatalf("PutNetwork: %v", err)
	}
	if err := s.PutNetwork(sampleNetwork(idB, "backend")); err != nil {
		t.Fatalf("PutNetwork: %v", err)
	}

	// The index is a real file written atomically, with no staging file left.
	if _, err := os.Stat(s.networkIndexPath()); err != nil {
		t.Fatalf("index file missing: %v", err)
	}
	if _, err := os.Stat(s.networkIndexPath() + tmpSuffix); !os.IsNotExist(err) {
		t.Errorf("staging file left behind: %v", err)
	}

	for _, ref := range []string{idA, "hullnet", idA[:8]} {
		got, err := s.GetNetwork(ref)
		if err != nil {
			t.Fatalf("GetNetwork(%q): %v", ref, err)
		}
		if got.ID != idA || got.IPAM.Subnet != "10.66.0.0/24" {
			t.Errorf("GetNetwork(%q) = %+v", ref, got)
		}
	}

	list, err := s.ListNetworks()
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(list) != 2 || list[0].Name != "backend" || list[1].Name != "hullnet" {
		t.Fatalf("ListNetworks = %+v, want sorted by name", list)
	}

	// Updating in place replaces the record.
	upd := sampleNetwork(idA, "hullnet")
	upd.Internal = true
	if err := s.PutNetwork(upd); err != nil {
		t.Fatalf("PutNetwork update: %v", err)
	}
	if got, _ := s.GetNetwork(idA); !got.Internal {
		t.Error("update was not persisted")
	}

	// A different network may not steal an existing name.
	if err := s.PutNetwork(sampleNetwork(NewID(), "hullnet")); !errors.Is(err, ErrNameInUse) {
		t.Errorf("duplicate network name = %v, want ErrNameInUse", err)
	}

	if err := s.DeleteNetwork(idA); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
	if err := s.DeleteNetwork(idA); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteNetwork = %v, want ErrNotFound", err)
	}
	if _, err := s.GetNetwork("hullnet"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetNetwork after delete = %v, want ErrNotFound", err)
	}
}

func TestNetworkAmbiguousPrefix(t *testing.T) {
	s := newTestStore(t)
	a := "abcd" + strings.Repeat("0", 60)
	b := "abce" + strings.Repeat("0", 60)
	if err := s.PutNetwork(sampleNetwork(a, "netone")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNetwork(sampleNetwork(b, "nettwo")); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetNetwork("abc")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("GetNetwork(\"abc\") = %v, want ErrAmbiguous", err)
	}
	var amb *AmbiguousError
	if !errors.As(err, &amb) || len(amb.Matches) != 2 {
		t.Fatalf("unexpected ambiguity error: %v", err)
	}
}

func TestPutNetworkValidation(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutNetwork(nil); err == nil {
		t.Error("PutNetwork(nil) = nil, want an error")
	}
	if err := s.PutNetwork(sampleNetwork("", "x2")); !errors.Is(err, ErrInvalidID) {
		t.Errorf("empty id = %v, want ErrInvalidID", err)
	}
	if err := s.PutNetwork(sampleNetwork(NewID(), "../evil")); !errors.Is(err, ErrInvalidName) {
		t.Errorf("bad name = %v, want ErrInvalidName", err)
	}
}

func TestVolumeRoundTrip(t *testing.T) {
	s := newTestStore(t)
	v := &types.Volume{
		Name:       "pgdata",
		Driver:     "local",
		Mountpoint: filepath.Join(s.Root(), "volumes", "pgdata", "_data"),
		Created:    time.Unix(1700000000, 0).UTC(),
		Scope:      "local",
		Labels:     map[string]string{"app": "db"},
		Options:    map[string]string{"type": "none"},
	}
	if _, err := s.GetVolume("pgdata"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetVolume on empty index = %v, want ErrNotFound", err)
	}
	if err := s.PutVolume(v); err != nil {
		t.Fatalf("PutVolume: %v", err)
	}
	if err := s.PutVolume(&types.Volume{Name: "cache", Driver: "local", Scope: "local"}); err != nil {
		t.Fatalf("PutVolume: %v", err)
	}

	got, err := s.GetVolume("pgdata")
	if err != nil {
		t.Fatalf("GetVolume: %v", err)
	}
	if got.Driver != "local" || got.Labels["app"] != "db" || !got.Created.Equal(v.Created) {
		t.Errorf("GetVolume = %+v, want %+v", got, v)
	}

	list, err := s.ListVolumes()
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(list) != 2 || list[0].Name != "cache" || list[1].Name != "pgdata" {
		t.Fatalf("ListVolumes = %+v, want sorted by name", list)
	}

	dir, err := s.VolumeDir("pgdata")
	if err != nil {
		t.Fatalf("VolumeDir: %v", err)
	}
	if dir != filepath.Join(s.Root(), "volumes", "pgdata", "_data") {
		t.Errorf("VolumeDir = %q", dir)
	}
	if _, err := s.VolumeDir("../../etc"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("VolumeDir traversal = %v, want ErrInvalidName", err)
	}

	if err := s.DeleteVolume("pgdata"); err != nil {
		t.Fatalf("DeleteVolume: %v", err)
	}
	if err := s.DeleteVolume("pgdata"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteVolume = %v, want ErrNotFound", err)
	}
	if err := s.PutVolume(&types.Volume{Name: "a"}); !errors.Is(err, ErrInvalidName) {
		t.Errorf("PutVolume with a bad name = %v, want ErrInvalidName", err)
	}
}

// TestIndexesSurviveReopen checks that both indexes are durable across a
// daemon restart, including a crash that left a staging file behind.
func TestIndexesSurviveReopen(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	s.SetLogger(quietLogger())
	id := NewID()
	if err := s.PutNetwork(sampleNetwork(id, "persistent")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutVolume(&types.Volume{Name: "persistent.vol", Driver: "local"}); err != nil {
		t.Fatal(err)
	}
	junk := s.networkIndexPath() + tmpSuffix
	if err := os.WriteFile(junk, []byte(`{"version":1,"net`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	s2.SetLogger(quietLogger())
	defer s2.Close()
	if got, err := s2.GetNetwork("persistent"); err != nil || got.ID != id {
		t.Fatalf("GetNetwork after reopen = %v, %v", got, err)
	}
	if _, err := s2.GetVolume("persistent.vol"); err != nil {
		t.Fatalf("GetVolume after reopen: %v", err)
	}
	if _, err := s2.Recover(t.Context(), func(int, time.Time) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Errorf("index staging file survived Recover: %v", err)
	}
}

// TestConcurrentIndexWrites hammers both indexes to prove the mutex + flock
// discipline does not lose records.
func TestConcurrentIndexWrites(t *testing.T) {
	s := newTestStore(t)
	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := sampleNetwork(NewID(), "net"+string(rune('a'+i%26))+string(rune('a'+i/26)))
			if err := s.PutNetwork(n); err != nil {
				errs <- err
			}
			if err := s.PutVolume(&types.Volume{Name: "vol" + string(rune('a'+i%26)) + string(rune('a'+i/26))}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent index write: %v", err)
	}
	nets, err := s.ListNetworks()
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != workers {
		t.Fatalf("ListNetworks = %d entries, want %d", len(nets), workers)
	}
	vols, err := s.ListVolumes()
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != workers {
		t.Fatalf("ListVolumes = %d entries, want %d", len(vols), workers)
	}
}
