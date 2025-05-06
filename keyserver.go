package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type KeyServerCert struct {
	Keyid       string `json:"keyid"`
	Keyinfo     string `json:"keyinfo"`
	Certificate string `json:"certificate"`
}

type KeyServerSign struct {
	Keyid      string `json:"keyid"`
	InputData  string `json:"inputdata"`
	SignFormat string `json:"signatureformat"`
	Result     string `json:"result"`
}

func getToken(client http.Client, user, password string) (string, error) {
	url := _cfg["auth-server"] + "/oauth2/token"
	req_body := []byte(`grant_type=client_credentials`)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(req_body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, password)

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", errors.New("incorrtect status code")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var dat map[string]interface{}
	err = json.Unmarshal(body, &dat)
	if err != nil {
		return "", err
	}

	token := dat["access_token"]
	if token == nil {
		return "", errors.New("token request failed")
	}

	if s, ok := token.(string); ok {
		return s, nil
	} else {
		return "", errors.New("incorrect token format")
	}
}

func getCerts(client http.Client, token string) ([]KeyServerCert, error) {
	url := _cfg["api-server"] + "/api/keys"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		fmt.Println(body)
		return nil, errors.New(fmt.Sprint("incorrect status code:", res.StatusCode))
	}

	var certs []KeyServerCert

	err = json.Unmarshal([]byte(body), &certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func getSign(client http.Client, token, op, desc, key, hash, inputpadding, format string) ([]byte, error) {
	jsonData, _ := json.Marshal(map[string]string{
		"operationid":     op,
		"keyid":           key,
		"inputdata":       hash,
		"inputformat":     "hex",
		"inputpadding":    inputpadding,
		"signatureformat": format,
		"description":     desc,
	})
	url := _cfg["api-server"] + "/api/signorders"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 201 {
		fmt.Println("Status: ", res.StatusCode)

		// Read the response body
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// Print the raw JSON response
		fmt.Println("Error response:", string(bodyBytes))

		return nil, errors.New("Incorrect status code")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var kcsSign KeyServerSign
	err = json.Unmarshal(body, &kcsSign)
	if err != nil {
		fmt.Println("Incorrect server response")
		return nil, err
	}

	sign, err := hex.DecodeString(kcsSign.Result)
	if err != nil {
		fmt.Println("Incorrect server response data")
		return nil, err
	}

	return sign, nil
}
