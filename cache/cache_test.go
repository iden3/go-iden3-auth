package cache_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/iden3/go-iden3-auth/v2/cache"
)

func TestSetAndGetWithDefaultTTL(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 2*time.Second)

	c.Set("foo", "bar")

	val, ok := c.Get("foo")
	if !ok || val != "bar" {
		t.Errorf("expected 'bar', got '%v', ok: %v", val, ok)
	}
}

func TestSetAndGetWithCustomTTL(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("short", "life", 100*time.Millisecond)

	time.Sleep(200 * time.Millisecond)

	_, ok := c.Get("short")
	if ok {
		t.Errorf("expected 'short' to be expired")
	}
}

func TestDelete(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("foo", "bar")
	c.Delete("foo")

	_, ok := c.Get("foo")
	if ok {
		t.Errorf("expected 'foo' to be deleted")
	}
}

func TestClear(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("a", "1")
	c.Set("b", "2")
	c.Clear()

	if _, ok := c.Get("a"); ok {
		t.Errorf("expected 'a' to be cleared")
	}
	if _, ok := c.Get("b"); ok {
		t.Errorf("expected 'b' to be cleared")
	}
}

func TestMultipleKeys(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 5*time.Second)

	c.Set("key1", "val1")
	c.Set("key2", "val2")
	c.Set("key3", "val3")

	tests := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}

	for key, expected := range tests {
		val, ok := c.Get(key)
		if !ok {
			t.Errorf("expected key %s to exist", key)
		}
		if val != expected {
			t.Errorf("expected value %s for key %s, got %s", expected, key, val)
		}
	}
}

func TestOverwriteValue(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 5*time.Second)

	c.Set("key1", "initial")
	val, ok := c.Get("key1")
	if !ok || val != "initial" {
		t.Fatalf("expected 'initial', got '%v', ok: %v", val, ok)
	}

	c.Set("key1", "updated")
	val, ok = c.Get("key1")
	if !ok || val != "updated" {
		t.Errorf("expected 'updated', got '%v', ok: %v", val, ok)
	}
}

func TestExpiredEntriesAreCleanedUp(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 100*time.Millisecond)

	// Insert many short-lived entries
	for i := 0; i < 20; i++ {
		c.Set(fmt.Sprintf("key-%d", i), "value", 50*time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond) // Wait for expiration

	// Access the expired entries to trigger lazy cleanup
	for i := 0; i < 20; i++ {
		c.Get(fmt.Sprintf("key-%d", i))
	}

	// After lazy cleanup, internal size should be less than or equal to 10
	if size := c.Len(); size > 10 {
		t.Errorf("expected cache to have <= 10 active items, got %d", size)
	}
}
