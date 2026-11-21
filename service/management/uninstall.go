package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var completionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func validCompletionToken(value string) bool { return completionTokenPattern.MatchString(value) }

type uninstallRequest struct {
	OperationID      string       `json:"operation_id"`
	Token            string       `json:"token"`
	ServerURL        string       `json:"server_url"`
	CA               string       `json:"ca,omitempty"`
	InstallDirectory string       `json:"install_directory"`
	Purge            bool         `json:"purge"`
	ChannelTrust     ChannelTrust `json:"channel_trust"`
	UpdateSigningKey string       `json:"update_signing_key,omitempty"`
	CertificatePEM   string       `json:"certificate_pem"`
	PrivateKeyPEM    string       `json:"private_key_pem"`
}

func copyUninstallFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	return errors.Join(copyErr, closeErr)
}

func (c *Client) launchUninstaller(ctx context.Context, command operationCommand) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	install, err := nativeInstallation(executable)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(c.dataDir, configFile))
	if err != nil {
		return err
	}
	var config Config
	if err = json.Unmarshal(data, &config); err != nil {
		return err
	}
	if err = config.Validate(); err != nil {
		return err
	}
	directory, err := newUninstallDirectory()
	if err != nil {
		return err
	}
	launched := false
	defer func() {
		if !launched {
			_ = os.RemoveAll(directory)
		}
	}()
	worker, err := prepareUninstallWorker(executable, directory)
	if err != nil {
		return err
	}
	if err = prepareNativeUninstaller(install, directory); err != nil {
		return err
	}
	requestPath := filepath.Join(directory, "request.json")
	identity := c.identitySnapshot()
	request := uninstallRequest{OperationID: command.ID, Token: command.CompletionToken, ServerURL: config.ServerURL,
		CA: config.CACertificatePEM, InstallDirectory: install, Purge: command.Action == "uninstall_delete_history",
		ChannelTrust: config.ChannelTrust, UpdateSigningKey: config.UpdateSigningKey,
		CertificatePEM: identity.CertificatePEM, PrivateKeyPEM: identity.PrivateKeyPEM}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	encoded, err = protectIdentity(encoded)
	if err != nil {
		return err
	}
	if err = writePrivateBytes(requestPath, encoded); err != nil {
		return err
	}
	if err = startUninstallWorker(ctx, worker, requestPath, command.ID); err != nil {
		return err
	}
	launched = true
	return nil
}

// RunUninstallWorker runs outside the service's process group.
// Its protected request contains an operation receipt and temporary TLS identity,
// never the device bearer credential. No remote command or path is executed.
func RunUninstallWorker(requestPath string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	directory := filepath.Dir(requestPath)
	if !filepath.IsAbs(requestPath) || filepath.Clean(requestPath) != filepath.Join(directory, "request.json") || !strings.HasPrefix(filepath.Base(directory), "packettale-uninstall-") {
		return errors.New("invalid uninstall request location")
	}
	if err = validateUninstallExecutable(executable, directory); err != nil {
		return err
	}
	if err = validateUninstallWorker(directory, requestPath); err != nil {
		return err
	}
	defer cleanupUninstallWorker(directory)
	file, err := os.Open(requestPath)
	if err != nil {
		return err
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 98305))
	if err != nil {
		file.Close()
		return err
	}
	encoded, err = unprotectIdentity(encoded)
	if err != nil {
		file.Close()
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var request uninstallRequest
	err = decoder.Decode(&request)
	if err == nil {
		if decoder.Decode(new(any)) != io.EOF {
			err = errors.New("invalid uninstall request")
		}
	}
	file.Close()
	_ = os.Remove(requestPath)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(request.OperationID)
	if err != nil || id.String() != request.OperationID || !validCompletionToken(request.Token) {
		return errors.New("invalid uninstall receipt identity")
	}
	config := Config{ServerURL: request.ServerURL, CACertificatePEM: request.CA,
		ChannelTrust: request.ChannelTrust, UpdateSigningKey: request.UpdateSigningKey}
	if err = config.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	code, err := executeNativeUninstall(ctx, request.InstallDirectory, directory, request.Purge)
	if err == nil && !request.Purge {
		// Retained connection history must not retain an enrollment identity or
		// consumed invitation configuration.
		// A subsequent install can enroll with its newly supplied invitation.
		dataDirectory, pathErr := nativeDataDirectory()
		if pathErr != nil {
			err = pathErr
		} else {
			for _, name := range []string{stateFile, configFile} {
				if removeErr := os.Remove(filepath.Join(dataDirectory, name)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					err = errors.Join(err, removeErr)
				}
			}
		}
	}
	status, reason := "completed", ""
	if err != nil {
		status = "failed"
		reason = "The native uninstaller failed. Check the endpoint before retrying."
	}
	if code == 3010 {
		status = "reboot_required"
		reason = "Windows requires a reboot and a retry to finish removal. No reboot was requested automatically."
	}
	workerClient := New(directory, nil)
	workerClient.state = State{CertificatePEM: request.CertificatePEM, PrivateKeyPEM: request.PrivateKeyPEM}
	client := workerClient.privateHTTPClient(config, false)
	defer client.CloseIdleConnections()
	receipt, _ := json.Marshal(map[string]string{"status": status, "reason": reason})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, request.ServerURL+"/api/v1/removals/"+request.OperationID+"/complete/", bytes.NewReader(receipt))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+request.Token)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("uninstall receipt could not be delivered")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("uninstall receipt rejected (%d)", response.StatusCode)
	}
	return nil
}
