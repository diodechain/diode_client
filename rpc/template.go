// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/diodechain/diode_client/config"
)

func unzip(in []byte) string {
	out := bytes.Buffer{}
	gz := bytes.NewBuffer(in)

	zr, err := gzip.NewReader(gz)
	if err != nil {
		config.AppConfig.Logger.Error("failed to unzip: %v", err)
		os.Exit(129)
	}
	if _, err := io.Copy(&out, zr); err != nil {
		config.AppConfig.Logger.Error("failed to unzip: %v", err)
		os.Exit(129)
	}
	return out.String()

}

func unzip64(in []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(unzip(in)))
}

const emptyPixel string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkqAcAAIUAgUW0RjgAAAAASUVORK5CYII="

func image(code int) (string, string) {
	switch {
	case code >= 200 && code < 300:
		return unicornHappy, "Welcome to the your Web3 proxy. To learn how to create your own Web3 content visit us at <a href='https://diode.io'>DIODE</a>"
	case code == 403:
		return emptyPixel, "This domain has been reported to violate our terms of service. Connected IP addresses have been collected and will be reported to the authorities."
	case code >= 400 && code < 500:
		return emptyPixel, "Um, looks like you don't have access to this resource, or it may be down. To learn how to create your own Web3 content visit us at <a href='https://diode.io'>DIODE</a>"
	case code >= 500 && code < 600:
		return unicornSad, "Uh you found a bug, please copy the url and above error message and <a href='https://github.com/diodechain/diode_client/issues/new'>submit them to us here</a> with a short description of what happened."
	default:
		return unicornDrinking, "We have no idea what happened here."
	}
}

func Page(title string, code int, codeMessage string, more string) string {
	image, hint := image(code)
	return fmt.Sprintf(template, title, strconv.FormatInt(int64(code), 10), codeMessage, more, hint, image)
}
