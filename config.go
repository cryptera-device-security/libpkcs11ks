package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Config map[string]string

func (cfg Config) updateJSON(env, filename string) error {
	if val, ok := os.LookupEnv(env); ok {
		filename = val
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := ioutil.ReadAll(f)

	var values map[string]string
	err = json.Unmarshal(b, &values)
	if err != nil {
		return fmt.Errorf("Parsing %s failed: %s", filename, err)
	}

	for k, v := range values {
		if _, ok := cfg[k]; !ok {
			return fmt.Errorf("Reading %s failed. Incorrect key: %s", filename, k)
		}
		cfg[k] = v
	}

	return nil
}

func (cfg Config) updateEnv() {
	envOpts := map[string]string{
		"api-server": "KSC_API_SERVER",
		"op-id":      "KSC_OPERATION_ID",
		"op-desc":    "KSC_OPERATION_DESCRIPTION",
	}

	for k, v := range envOpts {
		if env, ok := os.LookupEnv(v); ok {
			cfg[k] = env
		}
	}
}

func LoadConfig() Config {
	cfg := Config{
		"auth-server": "",
		"api-server":  "",
		"username":    "",
		"password":    "",
		"op-id":       "",
		"op-desc":     "",
	}

	/*
		err := cfg.updateJSON("KSC_CONFIG", os.Getenv("HOME")+"/.ksc_config.json")
		if err != nil {
			fmt.Println(err)
		}

		cfg.updateJSON("KSC_REQUEST", "/tmp/ksc_req.json")
	*/
	cfg.updateEnv()

	return cfg
}
