//go:build linux

package helperserver

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
)

func copyExtendedAttributes(source, destination string) (map[string][]byte, error) {
	attributes, err := readExtendedAttributes(source)
	if err != nil {
		return nil, err
	}
	for name, value := range attributes {
		if err := syscall.Setxattr(destination, name, value, 0); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	return attributes, nil
}

func validateExtendedAttributes(path string, expected map[string][]byte) error {
	current, err := readExtendedAttributes(path)
	if err != nil {
		return err
	}
	if len(current) != len(expected) {
		return fmt.Errorf("attribute count got %d want %d", len(current), len(expected))
	}
	for name, expectedValue := range expected {
		if !bytes.Equal(current[name], expectedValue) {
			return fmt.Errorf("attribute %s differs", name)
		}
	}
	return nil
}

func readExtendedAttributes(path string) (map[string][]byte, error) {
	names, err := listExtendedAttributeNames(path)
	if err != nil {
		return nil, err
	}
	attributes := make(map[string][]byte, len(names))
	for _, name := range names {
		value, err := getExtendedAttribute(path, name)
		if err != nil {
			return nil, fmt.Errorf("get %s: %w", name, err)
		}
		attributes[name] = value
	}
	return attributes, nil
}

func listExtendedAttributeNames(path string) ([]string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := syscall.Listxattr(path, nil)
		if isExtendedAttributeUnsupported(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buffer := make([]byte, size)
		n, err := syscall.Listxattr(path, buffer)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var names []string
		for _, raw := range bytes.Split(buffer[:n], []byte{0}) {
			if len(raw) > 0 {
				names = append(names, string(raw))
			}
		}
		return names, nil
	}
	return nil, syscall.ERANGE
}

func getExtendedAttribute(path, name string) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := syscall.Getxattr(path, name, nil)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return []byte{}, nil
		}
		value := make([]byte, size)
		n, err := syscall.Getxattr(path, name, value)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return value[:n], nil
	}
	return nil, syscall.ERANGE
}

func isExtendedAttributeUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}
