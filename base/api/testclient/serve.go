package testclient

import (
	"net/http"

	"github.com/packettale/agents/base/api"
)

func init() {
	api.RegisterHandler("/test/", http.StripPrefix("/test/", http.FileServer(http.Dir("./api/testclient/root/"))))
}
