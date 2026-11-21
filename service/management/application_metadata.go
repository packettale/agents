package management

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"strings"

	"github.com/packettale/agents/service/profile"
	"github.com/vincent-petithory/dataurl"
	"golang.org/x/image/draw"
)

// Icons are read from the existing profile cache, never fetched from the web.
func applicationIcon(profileID string) []byte {
	if !localApplicationID.MatchString(profileID) {
		return nil
	}
	p, err := profile.GetLocalProfile(strings.TrimPrefix(profileID, "local/"), nil, nil)
	if err != nil {
		return nil
	}
	p.RLock()
	icons := append(p.Icons[:0:0], p.Icons...)
	p.RUnlock()
	for _, icon := range icons {
		encoded, err := icon.GetIconAsDataURL()
		if err != nil || len(encoded) > 1400000 {
			continue
		}
		data, err := dataurl.DecodeString(encoded)
		if err != nil {
			continue
		}
		if normalized := normalizeApplicationIcon(data.Data); normalized != nil {
			return normalized
		}
	}
	return nil
}

func normalizeApplicationIcon(data []byte) []byte {
	if len(data) == 0 || len(data) > 1000000 {
		return nil
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 1024 || config.Height > 1024 {
		return nil
	}
	source, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	target := image.NewNRGBA(image.Rect(0, 0, 48, 48))
	w, h := 48, 48
	if config.Width > config.Height {
		h = max(1, 48*config.Height/config.Width)
	} else {
		w = max(1, 48*config.Width/config.Height)
	}
	bounds := image.Rect((48-w)/2, (48-h)/2, (48+w)/2, (48+h)/2)
	draw.BiLinear.Scale(target, bounds, source, source.Bounds(), draw.Src, nil)
	var output bytes.Buffer
	if err := png.Encode(&output, target); err != nil || output.Len() > 32768 {
		return nil
	}
	return output.Bytes()
}
