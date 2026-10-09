package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestResolveReturnsIdentity(t *testing.T) {
	a := &Adapter{
		loadPath: func() (string, error) { return "/home/u/.mcp.json", nil },
		readFile: func(string) ([]byte, error) { return []byte(`{"mcpServers":{}}`), nil },
	}
	id, err := a.Resolve(context.Background(), model.MCP, auth.Discovery)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Provider != model.MCP || id.Account != "/home/u/.mcp.json" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func noEnv(string) (string, bool) { return "", false }

func TestResolveMissingPathFailsClosed(t *testing.T) {
	a := New(noEnv)
	if _, err := a.Resolve(context.Background(), model.MCP, auth.Discovery); err == nil {
		t.Fatal("missing MCP_CONFIG_FILE must fail closed")
	}
}

func TestResolveUnreadableFileFailsClosed(t *testing.T) {
	a := &Adapter{
		loadPath: func() (string, error) { return "/nope", nil },
		readFile: func(string) ([]byte, error) { return nil, errors.New("no such file") },
	}
	if _, err := a.Resolve(context.Background(), model.MCP, auth.Discovery); err == nil {
		t.Fatal("an unreadable config file must fail closed")
	}
}

func TestResolveRejectsWrongProvider(t *testing.T) {
	a := New(func(k string) (string, bool) {
		if k == "MCP_CONFIG_FILE" {
			return "/x", true
		}
		return "", false
	})
	if _, err := a.Resolve(context.Background(), model.AWS, auth.Discovery); err == nil {
		t.Fatal("mcp adapter must reject a non-mcp provider")
	}
}
