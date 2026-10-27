package main

import (
	"bytes"
	"testing"
)

func benchConfig(b *testing.B, rawURL string) StressConfig {
	b.Helper()
	u, path, err := parseTarget(rawURL)
	if err != nil {
		b.Fatal(err)
	}
	return StressConfig{Target: u, Port: determinePort(u), Path: path}
}

func BenchmarkBuildRequestGET(b *testing.B) {
	cfg := benchConfig(b, "http://example.com/api?x=1")
	var buf, body bytes.Buffer
	buf.Grow(4096)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buildRequest(&buf, cfg, "GET", "example.com", &body)
	}
	b.SetBytes(int64(buf.Len()))
}

func BenchmarkBuildRequestPOST(b *testing.B) {
	cfg := benchConfig(b, "http://example.com/submit")
	var buf, body bytes.Buffer
	buf.Grow(4096)
	body.Grow(512)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		body.Reset()
		buildRequest(&buf, cfg, "POST", "example.com", &body)
	}
	b.SetBytes(int64(buf.Len()))
}
