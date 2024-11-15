package common

import "testing"

func TestRabbitConnection_Channel(t *testing.T) {
    conn := NewRabbitConnection(rabbitURL)
    channel, err := conn.Channel()
    if err != nil {
        t.Fatalf("Failed to create channel: %v", err)
    }
    if channel == nil {
        t.Fatal("Channel should not be nil")
    }
}

func TestRabbitConnection_Close(t *testing.T) {
    conn := NewRabbitConnection(rabbitURL)
    channel, err := conn.Channel()
    if err != nil {
        t.Fatalf("Failed to create channel: %v", err)
    }
    if channel == nil {
        t.Fatal("Channel should not be nil")
    }

    err = conn.Close()
    if err != nil {
        t.Fatalf("Failed to close connection: %v", err)
    }

    if !conn.conn.IsClosed() {
        t.Fatal("Connection should be closed")
    }

    if !conn.channel.IsClosed() {
        t.Fatal("Channel should be closed")
    }
}
