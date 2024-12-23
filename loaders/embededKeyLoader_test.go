package loaders

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/iden3/go-circuits/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockKeyLoader implements VerificationKeyLoader for testing
type MockKeyLoader struct {
	keys map[circuits.CircuitID][]byte
	err  error
}

func (m *MockKeyLoader) Load(id circuits.CircuitID) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if key, ok := m.keys[id]; ok {
		return key, nil
	}
	return nil, errors.New("key not found")
}

func TestNewEmbeddedKeyLoader(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		assert.True(t, loader.useCache)
		assert.NotNil(t, loader.cache)
		assert.Nil(t, loader.keyLoader)
	})

	t.Run("with custom loader", func(t *testing.T) {
		mockLoader := &MockKeyLoader{}
		loader := NewEmbeddedKeyLoader(WithKeyLoader(mockLoader))
		assert.True(t, loader.useCache)
		assert.NotNil(t, loader.cache)
		assert.Equal(t, mockLoader, loader.keyLoader)
	})

	t.Run("without cache", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader(WithCacheDisabled())
		assert.False(t, loader.useCache)
		assert.Nil(t, loader.cache)
	})

	t.Run("multiple options", func(t *testing.T) {
		mockLoader := &MockKeyLoader{}
		loader := NewEmbeddedKeyLoader(
			WithKeyLoader(mockLoader),
			WithCacheDisabled(),
		)
		assert.False(t, loader.useCache)
		assert.Nil(t, loader.cache)
		assert.Equal(t, mockLoader, loader.keyLoader)
	})
}

func TestEmbeddedKeyLoader_Load(t *testing.T) {
	testKey := []byte("test-key-data")
	testID := circuits.CircuitID("test-circuit")

	t.Run("load from cache", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		loader.storeInCache(testID, testKey)

		key, err := loader.Load(testID)
		require.NoError(t, err)
		assert.Equal(t, testKey, key)
	})

	t.Run("load from custom loader", func(t *testing.T) {
		mockLoader := &MockKeyLoader{
			keys: map[circuits.CircuitID][]byte{
				testID: testKey,
			},
		}
		loader := NewEmbeddedKeyLoader(WithKeyLoader(mockLoader))

		key, err := loader.Load(testID)
		require.NoError(t, err)
		assert.Equal(t, testKey, key)

		// Verify key was cached
		cachedKey := loader.getFromCache(testID)
		assert.Equal(t, testKey, cachedKey)
	})

	t.Run("custom loader error fallback to embedded", func(t *testing.T) {
		mockLoader := &MockKeyLoader{
			err: errors.New("mock error"),
		}
		loader := NewEmbeddedKeyLoader(WithKeyLoader(mockLoader))

		key, err := loader.Load(circuits.AuthV2CircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("no cache", func(t *testing.T) {
		mockLoader := &MockKeyLoader{
			keys: map[circuits.CircuitID][]byte{
				testID: testKey,
			},
		}
		loader := NewEmbeddedKeyLoader(
			WithKeyLoader(mockLoader),
			WithCacheDisabled(),
		)

		key, err := loader.Load(testID)
		require.NoError(t, err)
		assert.Equal(t, testKey, key)

		// Verify key was not cached
		assert.Nil(t, loader.cache)
	})

	t.Run("embedded key not found", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()

		_, err := loader.Load("non-existent-circuit")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load default key")
	})
}

func TestDefaultEmbeddedKeys(t *testing.T) {

	t.Run("authV2", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		key, err := loader.Load(circuits.AuthV2CircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("AtomicQueryMTPV2CircuitID", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		key, err := loader.Load(circuits.AtomicQueryMTPV2CircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("AtomicQueryMTPV2OnChainCircuitID", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		key, err := loader.Load(circuits.AtomicQueryMTPV2OnChainCircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("AtomicQuerySigV2CircuitID", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		key, err := loader.Load(circuits.AtomicQuerySigV2CircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("AtomicQuerySigV2CircuitID", func(t *testing.T) {
		loader := NewEmbeddedKeyLoader()
		key, err := loader.Load(circuits.AtomicQuerySigV2OnChainCircuitID)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})
}

func TestEmbeddedKeyLoader_CacheConcurrency(t *testing.T) {
	loader := NewEmbeddedKeyLoader()
	testID := circuits.CircuitID("test-circuit")
	testKey := []byte("test-key-data")

	// Test concurrent reads
	t.Run("concurrent reads", func(t *testing.T) {
		loader.storeInCache(testID, testKey)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := loader.getFromCache(testID)
				assert.Equal(t, testKey, key)
			}()
		}
		wg.Wait()
	})

	// Test concurrent writes
	t.Run("concurrent writes", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id := circuits.CircuitID(fmt.Sprintf("circuit-%d", i))
				key := []byte(fmt.Sprintf("key-%d", i))
				loader.storeInCache(id, key)
			}(i)
		}
		wg.Wait()

		// Verify all writes succeeded
		for i := 0; i < 100; i++ {
			id := circuits.CircuitID(fmt.Sprintf("circuit-%d", i))
			expected := []byte(fmt.Sprintf("key-%d", i))
			actual := loader.getFromCache(id)
			assert.Equal(t, expected, actual)
		}
	})
}

// Benchmark cache operations
func BenchmarkEmbeddedKeyLoader_Cache(b *testing.B) {
	loader := NewEmbeddedKeyLoader()
	testID := circuits.CircuitID("test-circuit")
	testKey := []byte("test-key-data")

	b.Run("cache write", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			loader.storeInCache(testID, testKey)
		}
	})

	b.Run("cache read", func(b *testing.B) {
		loader.storeInCache(testID, testKey)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = loader.getFromCache(testID)
		}
	})
}
