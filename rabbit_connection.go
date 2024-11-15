package common

import (
    "sync"

    amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitConnection is a rabbitmq connection client
// and it is thread safe, so we can use it in multiple goroutines
type RabbitConnection struct {
    sync.Mutex

    connStr string
    conn    *amqp.Connection
    channel *amqp.Channel
}

func NewRabbitConnection(connStr string) *RabbitConnection {
    return &RabbitConnection{connStr: connStr}
}

func (a *RabbitConnection) connect() error {
    var err error
    a.conn = nil
    a.conn, err = amqp.Dial(a.connStr)
    if err != nil {
        return err
    }
    return nil
}

func (a *RabbitConnection) Channel() (*amqp.Channel, error) {
    var err error
    if a.channel != nil {
        if a.conn.IsClosed() {
            a.conn = nil
            a.channel = nil
            return a.Channel()
        }
        return a.channel, nil
    }

    a.Lock()
    defer a.Unlock()

    if a.conn == nil {
        err = a.connect()
        if err != nil {
            return nil, err
        }
    }

    if a.channel == nil {
        a.channel, err = a.conn.Channel()
        if err != nil {
            return nil, err
        }
    }
    return a.channel, nil
}

func (a *RabbitConnection) Close() error {
    errChan := make(chan error, 2)
    var wg sync.WaitGroup
    wg.Add(2)
    go func() {
        defer wg.Done()
        if a.conn != nil {
            errChan <- a.conn.Close()
        }
    }()
    go func() {
        defer wg.Done()
        if a.channel != nil {
            errChan <- a.channel.Close()
        }
    }()

    wg.Wait()
    close(errChan)

    for err := range errChan {
        if err != nil {
            return err
        }
    }
    return nil
}
