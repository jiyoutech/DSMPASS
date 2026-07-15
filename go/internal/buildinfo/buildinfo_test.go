package buildinfo

import "testing"

func TestMultipleIdentitySourcesAllowed(t *testing.T) {
	original := AllowMultipleIdentitySources
	t.Cleanup(func() { AllowMultipleIdentitySources = original })

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "true", value: "true", want: true},
		{name: "one", value: "1", want: true},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "invalid fails closed", value: "invalid", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AllowMultipleIdentitySources = tt.value
			if got := MultipleIdentitySourcesAllowed(); got != tt.want {
				t.Fatalf("MultipleIdentitySourcesAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
