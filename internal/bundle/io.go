package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ChPuru/hull/internal/fsutil"
	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// ConfigName is the file name the OCI runtime-spec mandates inside a bundle.
const ConfigName = "config.json"

// Write serialises spec to <bundleDir>/config.json with mode 0600, atomically:
// the bytes land in a temporary file in the same directory, are fsynced, and
// are then renamed over the target, so a crash mid-write can never leave a
// half-written bundle that a runtime would then try to parse.
//
// 0600 matters: config.json names every host path bind-mounted into the
// container and every environment variable it was given, which routinely
// includes credentials.
func Write(spec *runtimespec.Spec, bundleDir string) error {
	if spec == nil {
		return errors.New("bundle: Write called with a nil spec")
	}
	if bundleDir == "" {
		return errors.New("bundle: Write called with an empty bundle directory")
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("bundle: refusing to write an invalid config.json: %w", err)
	}
	data, err := json.MarshalIndent(spec, "", "\t")
	if err != nil {
		return fmt.Errorf("bundle: encoding config.json: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return fmt.Errorf("bundle: creating bundle directory %s: %w", bundleDir, err)
	}
	p := filepath.Join(bundleDir, ConfigName)
	if err := fsutil.WriteFileAtomic(p, data, 0o600); err != nil {
		return fmt.Errorf("bundle: writing %s: %w", p, err)
	}
	return nil
}

// Read loads and validates <bundleDir>/config.json.
//
// The spec is validated on the way in as well as on the way out, so a bundle
// that was edited by hand — or corrupted — is rejected here rather than
// producing a confusing failure inside the runtime.
func Read(bundleDir string) (*runtimespec.Spec, error) {
	if bundleDir == "" {
		return nil, errors.New("bundle: Read called with an empty bundle directory")
	}
	p := filepath.Join(bundleDir, ConfigName)
	var spec runtimespec.Spec
	if err := fsutil.ReadJSON(p, &spec); err != nil {
		return nil, fmt.Errorf("bundle: reading %s: %w", p, err)
	}
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("bundle: %s is not a valid runtime spec: %w", p, err)
	}
	return &spec, nil
}
