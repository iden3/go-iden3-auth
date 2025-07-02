package cache_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/iden3/go-iden3-auth/v2/cache"
	"github.com/stretchr/testify/require"
)

func TestSetAndGetWithDefaultTTL(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 2*time.Second)

	c.Set("foo", "bar")

	val, ok := c.Get("foo")
	require.True(t, ok, "expected 'foo' to be set")
	require.Equal(t, "bar", val, "expected value for 'foo' to be 'bar'")
}

func TestSetAndGetWithCustomTTL(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("short", "life", cache.WithTTL(100*time.Millisecond))

	time.Sleep(200 * time.Millisecond)

	_, ok := c.Get("short")
	require.False(t, ok, "expected 'short' to be expired")
}

func TestDelete(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("foo", "bar")
	c.Delete("foo")

	_, ok := c.Get("foo")
	require.False(t, ok, "expected 'foo' to be deleted")
}

func TestClear(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 10*time.Second)

	c.Set("a", "1")
	c.Set("b", "2")
	c.Clear()

	require.Equal(t, 0, c.Len(), "expected cache to be empty after Clear")

	_, ok := c.Get("a")
	require.False(t, ok, "expected 'a' to be cleared")

	_, ok = c.Get("b")
	require.False(t, ok, "expected 'b' to be cleared")
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
		require.True(t, ok, "expected key %s to exist", key)
		require.Equal(t, expected, val, "expected value %s for key %s, got %s", expected, key, val)
	}
}

func TestOverwriteValue(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 5*time.Second)

	c.Set("key1", "initial")
	val, ok := c.Get("key1")
	require.True(t, ok, "expected 'key1' to be set")
	require.Equal(t, "initial", val, "expected value for 'key1' to be 'initial'")

	c.Set("key1", "updated")
	val, ok = c.Get("key1")
	require.True(t, ok, "expected 'key1' to be updated")
	require.Equal(t, "updated", val, "expected value for 'key1' to be 'updated'")
}

func TestExpiredEntriesAreCleanedUp(t *testing.T) {
	c := cache.NewInMemoryCache[string](10, 100*time.Millisecond)

	// Insert many short-lived entries
	for i := 0; i < 20; i++ {
		c.Set(fmt.Sprintf("key-%d", i), "value", cache.WithTTL(50*time.Millisecond))
	}

	time.Sleep(200 * time.Millisecond) // Wait for expiration

	// Access the expired entries to trigger lazy cleanup
	for i := 0; i < 20; i++ {
		c.Get(fmt.Sprintf("key-%d", i))
	}

	require.LessOrEqual(t, c.Len(), 10, "expected cache to have <= 10 active items")
}
