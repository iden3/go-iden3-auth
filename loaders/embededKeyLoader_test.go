package loaders

import (
	"errors"
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
		loader := NewEmbeddedKeyLoader(WithoutCache())
		assert.False(t, loader.useCache)
		assert.Nil(t, loader.cache)
	})

	t.Run("multiple options", func(t *testing.T) {
		mockLoader := &MockKeyLoader{}
		loader := NewEmbeddedKeyLoader(
			WithKeyLoader(mockLoader),
			WithoutCache(),
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
			WithoutCache(),
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
