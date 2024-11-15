## Common
This package contains common utilities that are used across the services.

## Api

### ConfigLoader

`ConfigLoader` is a env file loader that loads the environment variables from a `.env` file and umarshalls them into a
struct.

```go
config, err := NewConfigLoaderFromEnvFile[Config](".env.test", nil)
```

### RabbitConnection

`RabbitConnection` is a rabbitmq connection that connects to a rabbitmq server and returns a connection object.

```go
conn, err := NewRabbitConnection("amqp://guest:guest@localhost:5672/")
if err != nil {
    return err
}
defer conn.Close()
fmt.Print(conn)
```

### Signature

`Signature` is a signature object that signs a message using a private key and returns a signature.
This ensures that our requests are coming from a trusted source and have not been tampered with in transit.
```go
method := "GET"
path := "/api/v1/endpoint"
params := url.Values{}
params.Add("key", "value")
signature1, err := GenerateSignature(method, path, params, []byte{}, secretKey)
```

### TokenMaker

`TokenMaker` is an interface that generates a token and validates a token.
```go
tokenMaker := NewJwtMaker()
token, err := tokenMaker..CreateToken(
    &CustomPayload{
        ID:        "123",
        ExpiredAt: time.Now().Add(5 * time.Minute),
    }, secretKey,
)
```