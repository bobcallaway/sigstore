package example

import "testing"

func TestMemory(t *testing.T) {
	if err := ShowMemorySigners(); err != nil {
		t.Fatalf("error from SMS: %v", err)
	}
}
