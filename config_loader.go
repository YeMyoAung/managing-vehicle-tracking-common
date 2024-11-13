package common

import (
    "log"
    "os"

    "github.com/go-playground/validator/v10"
    "github.com/goccy/go-json"
    "github.com/joho/godotenv"
)

type ConfigLoader[T any] struct {
    Config   *T
    Validate *validator.Validate
}

// parse reads the env file and parses it into a struct
// by splitting this function, we can also implement other loaders like NewConfigLoaderFromFlags
func parse[T any](
    source string,
    validate *validator.Validate,
) (*T, error) {
    file, err := os.Open(source)

    if err != nil {
        return nil, err
    }

    defer func(file *os.File) {
        err := file.Close()
        if err != nil {
            log.Println("Error closing file", err)
        }
    }(file)

    env, err := godotenv.Parse(file)

    if err != nil {
        return nil, err
    }
    buf, err := json.Marshal(env)

    if err != nil {
        return nil, err
    }

    var config T

    if err := json.Unmarshal(buf, &config); err != nil {
        return nil, err
    }

    if err := validate.Struct(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

// NewConfigLoaderFromEnvFile creates a new config loader that reads from the env file
// like so: NewConfigLoaderFromEnvFile(".env")
func NewConfigLoaderFromEnvFile[T any](
    fileName string,
    Validator *validator.Validate,
) (*ConfigLoader[T], error) {
    if Validator == nil {
        Validator = validator.New(
            validator.WithRequiredStructEnabled(),
        )
    }

    source := ".env"

    if fileName != "" {
        source = fileName
    }

    log.Println("Loading env from ", source)

    config, err := parse[T](source, Validator)
    if err != nil {
        return nil, err
    }

    return &ConfigLoader[T]{
        Config:   config,
        Validate: Validator,
    }, nil
}
