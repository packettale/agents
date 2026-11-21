package netenv

import (
	"context"
	"testing"
)

func BenchmarkSystemDNSFingerprint(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := systemDNSFingerprint(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
