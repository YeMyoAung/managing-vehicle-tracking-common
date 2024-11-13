package common

import (
    "testing"
)

type Config struct {
    Port string `validate:"required"`
}

func TestNewConfigLoaderFromEnvFile(t *testing.T) {
    config, err := NewConfigLoaderFromEnvFile[Config](".env.test", nil)
    if err != nil {
        t.Fatal(err)
    }
    if config == nil {
        t.Fatal("Config loader should not be null")
    }
    if config.Config.Port != "8080" {
        t.Fatal("Port should be 8080")
    }
}

func TestNewConfigLoaderFromEnvFile_MustFail(t *testing.T) {
    _, err := NewConfigLoaderFromEnvFile[Config](".env", nil)
    if err == nil {
        t.Fatal("Config loader should fail")
    }

}
