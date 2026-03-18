package payload

import (
	"encoding/hex"
	"testing"
)

func TestXorRoundTrip(t *testing.T) {
	key := []byte("testkey1234")
	plain := "hello world <script>alert(1)</script>"

	encoded := xorDecode([]byte(plain), key)
	decoded := xorDecode(encoded, key)

	if string(decoded) != plain {
		t.Fatalf("roundtrip failed: got %q, want %q", decoded, plain)
	}
}

func TestGetMissing(t *testing.T) {
	if v := Get("nonexistent.key"); v != "" {
		t.Fatalf("expected empty, got %q", v)
	}
}

func TestRegisterAndGet(t *testing.T) {
	key := []byte{0xAB, 0xCD}
	SetKey(key)

	plain := "test-payload"
	xored := xorDecode([]byte(plain), key)
	hexStr := hex.EncodeToString(xored)

	Register("test.item", hexStr)
	RegisterList("test", []string{"test.item"})

	got := Get("test.item")
	if got != plain {
		t.Fatalf("Get: got %q, want %q", got, plain)
	}

	list := List("test")
	if len(list) != 1 || list[0] != plain {
		t.Fatalf("List: got %v, want [%q]", list, plain)
	}
}
