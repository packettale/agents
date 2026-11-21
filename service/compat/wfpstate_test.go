package compat

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestWFPState(t *testing.T) {
	t.Parallel()

	w, err := parseWFPState(wfpTestData)
	if err != nil {
		t.Fatal(err)
	}

	want := &SimplifiedWFPState{
		Providers: []*WFPProvider{
			{Name: "SyntheticProvider", Description: "Synthetic provider", ProviderKey: "{11111111-1111-4111-8111-111111111111}"},
			{Name: "[no name]", Description: "[no description]", ProviderKey: "[no provider key]"},
		},
		SubLayers: []*WFPSubLayer{
			{Name: "SyntheticSubLayer", Description: "[no description]", SubLayerKey: "{22222222-2222-4222-8222-222222222222}"},
		},
		Callouts: []*WFPCallout{
			{
				Name: "SyntheticCallout", Description: "Synthetic callout",
				CalloutKey: "{33333333-3333-4333-8333-333333333333}", ProviderKey: "{11111111-1111-4111-8111-111111111111}",
				ApplicableLayer: "FWPM_LAYER_INBOUND_IPPACKET_V4",
			},
		},
		Filters: []*WFPFilter{
			{
				Name: "SyntheticFilter", Description: "Synthetic filter",
				FilterKey: "{44444444-4444-4444-8444-444444444444}", ProviderKey: "{11111111-1111-4111-8111-111111111111}",
				LayerKey: "FWPM_LAYER_INBOUND_IPPACKET_V4", SubLayerKey: "{22222222-2222-4222-8222-222222222222}",
			},
		},
	}
	got := w.simplified()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected simplified state:\n got: %#v\nwant: %#v", got, want)
	}

	wantKeys := map[string]struct{}{
		"{11111111-1111-4111-8111-111111111111}": {},
		"{22222222-2222-4222-8222-222222222222}": {},
		"{33333333-3333-4333-8333-333333333333}": {},
		"{44444444-4444-4444-8444-444444444444}": {},
		"[no provider key]":                      {},
	}
	if keys := got.Keys(); !reflect.DeepEqual(keys, wantKeys) {
		t.Errorf("unexpected keys: got %v, want %v", keys, wantKeys)
	}

	output := got.AsTable()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 5 || !sort.StringsAreSorted(lines) {
		t.Errorf("expected five sorted summary rows, got:\n%s", output)
	}
	for _, label := range []string{"Provider", "SubLayer", "Callout", "Filter", "[no description]"} {
		if !strings.Contains(output, label) {
			t.Errorf("summary is missing %q: %s", label, output)
		}
	}
	if strings.Contains(output, "Builtin") || strings.Contains(output, "FWPM_PROVIDER_MPSSVC_WF") {
		t.Errorf("summary includes ignored Windows entries: %s", output)
	}
}

func TestWFPStateInvalidXML(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"<wfpstate>", "<other/>"} {
		if _, err := parseWFPState([]byte(input)); err == nil {
			t.Errorf("expected invalid WFP state %q to fail", input)
		}
	}
}

// This synthetic fixture contains no captured system state, personal paths, or device data.
var wfpTestData = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<wfpstate>
  <providers numItems="3">
    <item>
      <providerKey>{11111111-1111-4111-8111-111111111111}</providerKey>
      <displayData><name>SyntheticProvider</name><description>Synthetic provider</description></displayData>
    </item>
    <item>
      <providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey>
      <displayData><name>BuiltinProvider</name></displayData>
    </item>
    <item/>
  </providers>
  <subLayers numItems="2">
    <item>
      <subLayerKey>{22222222-2222-4222-8222-222222222222}</subLayerKey>
      <displayData><name>SyntheticSubLayer</name></displayData>
    </item>
    <item><displayData><name>WFP BuiltinSubLayer</name></displayData></item>
  </subLayers>
  <layers numItems="1">
    <item>
      <layer><layerKey>FWPM_LAYER_INBOUND_IPPACKET_V4</layerKey></layer>
      <callouts numItems="2">
        <item>
          <calloutKey>{33333333-3333-4333-8333-333333333333}</calloutKey>
          <displayData><name>SyntheticCallout</name><description>Synthetic callout</description></displayData>
          <providerKey>{11111111-1111-4111-8111-111111111111}</providerKey>
          <applicableLayer>FWPM_LAYER_INBOUND_IPPACKET_V4</applicableLayer>
        </item>
        <item><displayData><name>RPC BuiltinCallout</name></displayData></item>
      </callouts>
      <filters numItems="2">
        <item>
          <filterKey>{44444444-4444-4444-8444-444444444444}</filterKey>
          <displayData><name>SyntheticFilter</name><description>Synthetic filter</description></displayData>
          <providerKey>{11111111-1111-4111-8111-111111111111}</providerKey>
          <layerKey>FWPM_LAYER_INBOUND_IPPACKET_V4</layerKey>
          <subLayerKey>{22222222-2222-4222-8222-222222222222}</subLayerKey>
        </item>
        <item>
          <displayData><name>BuiltinFilter</name></displayData>
          <providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey>
        </item>
      </filters>
    </item>
  </layers>
</wfpstate>`)
