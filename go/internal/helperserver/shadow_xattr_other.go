//go:build !linux

package helperserver

func copyExtendedAttributes(source, destination string) (map[string][]byte, error) {
	return nil, nil
}

func validateExtendedAttributes(path string, expected map[string][]byte) error {
	return nil
}
