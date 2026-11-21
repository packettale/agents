package filterlists

import (
	"github.com/packettale/agents/service/updates"
	"testing"
)

func TestColdUpdateStartsAtNewestBaseRegardlessOfArtifactPointer(t *testing.T) {
	previous := filterListsLoaded
	filterListsLoaded = make(chan struct{})
	defer func() { filterListsLoaded = previous }()
	index, err := updates.ParseIndex([]byte(`{"Version":"3.0.0","Artifacts":[{"Filename":"urgent.dsdl","Version":"3.0.1"},{"Filename":"base.dsdl","Version":"3.0.0"},{"Filename":"intermediate.dsdl","Version":"2.0.1"}]}`), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveUpdateOrder(index.Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Filename != baseListFilePath || got[1].Filename != urgentListFilePath {
		t.Fatalf("old delta processed before full base: %v", got)
	}
}
