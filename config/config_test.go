package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestStringSlice_UnmarshalYAML(t *testing.T) {
	type TestStruct struct {
		Values StringSlice `yaml:"values"`
	}

	t.Run("single string", func(t *testing.T) {
		raw := `values: "1.1.1.1"`
		var ts TestStruct
		err := yaml.Unmarshal([]byte(raw), &ts)
		assert.Nil(t, err)
		assert.Equal(t, StringSlice{"1.1.1.1"}, ts.Values)
	})

	t.Run("string slice", func(t *testing.T) {
		raw := `values: ["1.1.1.1", "2.2.2.2"]`
		var ts TestStruct
		err := yaml.Unmarshal([]byte(raw), &ts)
		assert.Nil(t, err)
		assert.Equal(t, StringSlice{"1.1.1.1", "2.2.2.2"}, ts.Values)
	})

	t.Run("invalid mapping node", func(t *testing.T) {
		raw := `values: { a: 1 }`
		var ts TestStruct
		err := yaml.Unmarshal([]byte(raw), &ts)
		assert.NotNil(t, err)
	})

	t.Run("invalid sequence item", func(t *testing.T) {
		raw := `values: [ { a: 1 } ]`
		var ts TestStruct
		err := yaml.Unmarshal([]byte(raw), &ts)
		assert.NotNil(t, err)
	})
}

func TestStringSlice_MarshalYAML(t *testing.T) {
	t.Run("single item marshals as scalar", func(t *testing.T) {
		s := StringSlice{"1.1.1.1"}
		val, err := s.MarshalYAML()
		assert.Nil(t, err)
		assert.Equal(t, "1.1.1.1", val)
	})

	t.Run("multiple items marshal as slice", func(t *testing.T) {
		s := StringSlice{"1.1.1.1", "2.2.2.2"}
		val, err := s.MarshalYAML()
		assert.Nil(t, err)
		assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, val)
	})

	t.Run("empty slice", func(t *testing.T) {
		s := StringSlice{}
		val, err := s.MarshalYAML()
		assert.Nil(t, err)
		assert.Equal(t, []string{}, val)
	})
}
