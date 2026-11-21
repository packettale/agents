package management

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestApplicationIconsAreBoundedRasterPNGs(t *testing.T) {
	source := image.NewNRGBA(image.Rect(0, 0, 96, 48))
	source.Set(0, 0, color.NRGBA{R: 255, A: 255})
	var data bytes.Buffer
	if err := png.Encode(&data, source); err != nil {
		t.Fatal(err)
	}
	normalized := normalizeApplicationIcon(data.Bytes())
	config, format, err := image.DecodeConfig(bytes.NewReader(normalized))
	if err != nil || format != "png" || config.Width != 48 || config.Height != 48 || len(normalized) > 32768 {
		t.Fatalf("invalid normalized icon: %+v %s %v", config, format, err)
	}
	for _, invalid := range [][]byte{nil, []byte(`<svg onload="alert(1)"></svg>`), make([]byte, 1000001)} {
		if normalizeApplicationIcon(invalid) != nil {
			t.Fatal("unsafe or oversized icon accepted")
		}
	}
}
