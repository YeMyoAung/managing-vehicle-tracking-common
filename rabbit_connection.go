package common

import (
    "sync"

    amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitConnection is a RabbitMQ connection client
// and it is thread-safe, so we can use it in multiple goroutines
type RabbitConnection struct {
    sync.Mutex

    connStr string
    conn    *amqp.Connection
    channel *amqp.Channel
}

// NewRabbitConnection creates a new RabbitConnection
func NewRabbitConnection(connStr string) *RabbitConnection {
    return &RabbitConnection{connStr: connStr}
}

// connect establishes a new connection to RabbitMQ
func (a *RabbitConnection) connect() error {
    a.Lock()
    defer a.Unlock()

    var err error
    if a.conn != nil && !a.conn.IsClosed() {
        return nil
    }

    a.conn = nil
    a.conn, err = amqp.Dial(a.connStr)
    return err
}

// Channel returns an active RabbitMQ channel, creating one if necessary
func (a *RabbitConnection) Channel() (*amqp.Channel, error) {
    // if the connection is closed, establish a new connection 
    if a.conn == nil || a.conn.IsClosed() {
        if err := a.connect(); err != nil {
            return nil, err
        }
    }

    // if the channel is closed, establish a new channel
    if a.channel == nil || a.channel.IsClosed() {
        var err error
        a.channel, err = a.conn.Channel()
        if err != nil {
            return nil, err
        }
    }

    return a.channel, nil
}

// Close shuts down the RabbitMQ connection and channel gracefully
func (a *RabbitConnection) Close() error {
    var wg sync.WaitGroup
    errChan := make(chan error, 1)

    wg.Add(1)

    // // Close the channel
    // go func() {
    //     defer wg.Done()
    //     if a.channel != nil {
    //         if a.channel.IsClosed() {
    //             return
    //         }
    //         errChan <- a.channel.Close()
    //     }
    // }()

    // Close the connection
    go func() {
        defer wg.Done()
        if a.conn != nil {
            if a.conn.IsClosed() {
                return
            }
            errChan <- a.conn.Close()
        }
    }()

    // Wait for both goroutines to finish
    wg.Wait()
    close(errChan)

    // Return the first error encountered, if any
    for err := range errChan {
        if err != nil {
            return err
        }
    }
    return nil
}
