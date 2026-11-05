package runtime

import (
	"bytes"
	"testing"
)

func TestChooseCPAProxyIndexIsBounded(t *testing.T) {
	for count := 1; count <= 17; count++ {
		index, err := chooseCPAProxyIndex(count, bytes.NewReader(make([]byte, 64)))
		if err != nil {
			t.Fatalf("count %d: %v", count, err)
		}
		if index < 0 || index >= count {
			t.Fatalf("count %d returned %d", count, index)
		}
	}
}

func TestChooseCPAProxyIndexRejectsEmptyPool(t *testing.T) {
	if _, err := chooseCPAProxyIndex(0, bytes.NewReader(nil)); err != errCPACredentialProxyUnavailable {
		t.Fatalf("error = %v, want unavailable", err)
	}
}
