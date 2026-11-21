package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/packettale/agents/base/database/record"
)

const (
	successMsg = "endpoint api success"
	failedMsg  = "endpoint api failed"
)

type actionTestRecord struct {
	record.Base
	sync.Mutex
	Msg string
}

func TestEndpoints(t *testing.T) {
	t.Parallel()

	testHandler := &mainHandler{
		mux: mainMux,
	}

	// ActionFn

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/action",
		Read: PermitAnyone,
		ActionFunc: func(_ *Request) (msg string, err error) {
			return successMsg, nil
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/action", nil, successMsg)

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/action-err",
		Read: PermitAnyone,
		ActionFunc: func(_ *Request) (msg string, err error) {
			return "", errors.New(failedMsg)
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/action-err", nil, "Unable to complete the request. Please try again.")

	// DataFn

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/data",
		Read: PermitAnyone,
		DataFunc: func(_ *Request) (data []byte, err error) {
			return []byte(successMsg), nil
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/data", nil, successMsg)

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/data-err",
		Read: PermitAnyone,
		DataFunc: func(_ *Request) (data []byte, err error) {
			return nil, errors.New(failedMsg)
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/data-err", nil, "Unable to complete the request. Please try again.")

	// StructFn

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/struct",
		Read: PermitAnyone,
		StructFunc: func(_ *Request) (i interface{}, err error) {
			return &actionTestRecord{
				Msg: successMsg,
			}, nil
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/struct", nil, successMsg)

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/struct-err",
		Read: PermitAnyone,
		StructFunc: func(_ *Request) (i interface{}, err error) {
			return nil, errors.New(failedMsg)
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/struct-err", nil, "Unable to complete the request. Please try again.")

	// RecordFn

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/record",
		Read: PermitAnyone,
		RecordFunc: func(_ *Request) (r record.Record, err error) {
			r = &actionTestRecord{
				Msg: successMsg,
			}
			r.CreateMeta()
			return r, nil
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/record", nil, successMsg)

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/record-err",
		Read: PermitAnyone,
		RecordFunc: func(_ *Request) (r record.Record, err error) {
			return nil, errors.New(failedMsg)
		},
	}))
	assert.HTTPBodyContains(t, testHandler.ServeHTTP, "GET", apiV1Path+"test/record-err", nil, "Unable to complete the request. Please try again.")
}

func TestActionRegistration(t *testing.T) {
	t.Parallel()

	assert.Error(t, RegisterEndpoint(Endpoint{}))

	assert.Error(t, RegisterEndpoint(Endpoint{
		Path: "test/err",
		Read: NotFound,
	}))
	assert.Error(t, RegisterEndpoint(Endpoint{
		Path: "test/err",
		Read: PermitSelf + 1,
	}))

	assert.Error(t, RegisterEndpoint(Endpoint{
		Path:  "test/err",
		Write: NotFound,
	}))
	assert.Error(t, RegisterEndpoint(Endpoint{
		Path:  "test/err",
		Write: PermitSelf + 1,
	}))

	assert.Error(t, RegisterEndpoint(Endpoint{
		Path: "test/err",
	}))

	assert.Error(t, RegisterEndpoint(Endpoint{
		Path: "test/err",
		ActionFunc: func(_ *Request) (msg string, err error) {
			return successMsg, nil
		},
		DataFunc: func(_ *Request) (data []byte, err error) {
			return []byte(successMsg), nil
		},
	}))

	assert.NoError(t, RegisterEndpoint(Endpoint{
		Path: "test/err",
		ActionFunc: func(_ *Request) (msg string, err error) {
			return successMsg, nil
		},
	}))
}

func TestEndpointServerErrorsDoNotExposeDetails(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		path := fmt.Sprintf("test/private-error-%d", status)
		assert.NoError(t, RegisterEndpoint(Endpoint{Path: path, Read: PermitAnyone,
			ActionFunc: func(_ *Request) (string, error) {
				return "", ErrorWithStatus(errors.New("private C:/ProgramData/credentials.json database driver failure"), status)
			}}))
		response := httptest.NewRecorder()
		handler := &mainHandler{mux: mainMux}
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, apiV1Path+path, nil))
		assert.Equal(t, status, response.Code)
		assert.NotContains(t, response.Body.String(), "credentials.json")
		assert.NotContains(t, response.Body.String(), "database driver")
		assert.Contains(t, response.Body.String(), "Please try again.")
	}
}
