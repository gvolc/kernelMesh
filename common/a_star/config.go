// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	epsilon   float64 = 1e-9
	maxWeight float64 = 100.0
)

type ProfileWeights struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	WeightLoss  float64 `json:"weight_loss"`
	WeightPing  float64 `json:"weight_ping"`
	WeightLoad  float64 `json:"weight_load"`
	WeightPower float64 `json:"weight_power"`
}

type rawMeshConfig struct {
	ActiveProfile string                    `json:"active_profile"`
	Profiles      map[string]ProfileWeights `json:"profiles"`
}

type configSnapshot struct {
	activeProfile string
	profiles      map[string]ProfileWeights
}

type ConfigMetrics struct {
	LastReloadTime time.Time
	ReloadSuccess  uint64
	ReloadFailure  uint64
}

type ConfigManager struct {
	filePath string
	metrics  atomic.Pointer[ConfigMetrics]
	snapshot atomic.Pointer[configSnapshot]
}

func NewConfigManager(filePath string) (*ConfigManager, error) {
	cm := &ConfigManager{
		filePath: filePath,
	}

	cm.metrics.Store(&ConfigMetrics{})

	if err := cm.Reload(); err != nil {
		return nil, fmt.Errorf("initial config load failed: %w", err)
	}
	return cm, nil
}

func MustNewConfigManager(filePath string) *ConfigManager {
	cm, err := NewConfigManager(filePath)
	if err != nil {
		panic(err)
	}
	return cm
}

func (cm *ConfigManager) GetCurrentWeights() ProfileWeights {
	current := cm.snapshot.Load()

	return current.profiles[current.activeProfile]
}

func (cm *ConfigManager) SwitchProfile(profileName string) error {
	for {
		current := cm.snapshot.Load()

		if _, exists := current.profiles[profileName]; !exists {
			return fmt.Errorf("profile '%s' does not exist in current config", profileName)
		}

		nextSnapshot := &configSnapshot{
			activeProfile: profileName,
			profiles:      current.profiles,
		}

		if cm.snapshot.CompareAndSwap(current, nextSnapshot) {
			return nil
		}
	}
}

func (cm *ConfigManager) Reload() error {
	fileBytes, err := os.ReadFile(cm.filePath)
	if err != nil {
		cm.incrementFailureMetric()
		return fmt.Errorf("failed to read file: %w", err)
	}

	var raw rawMeshConfig
	decoder := json.NewDecoder(bytes.NewReader(fileBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&raw); err != nil {
		cm.incrementFailureMetric()
		return fmt.Errorf("failed to parse JSON (strict mode): %w", err)
	}

	var dummy struct{}
	if err := decoder.Decode(&dummy); err != io.EOF {
		cm.incrementFailureMetric()
		return fmt.Errorf("failed to parse JSON: unexpected data after valid JSON body")
	}

	if err := validateRawConfig(raw); err != nil {
		cm.incrementFailureMetric()
		return fmt.Errorf("config validation failed: %w", err)
	}

	runtimeProfiles := make(map[string]ProfileWeights, len(raw.Profiles))
	for k, v := range raw.Profiles {
		runtimeProfiles[k] = v
	}

	nextSnapshot := &configSnapshot{
		activeProfile: raw.ActiveProfile,
		profiles:      runtimeProfiles,
	}

	cm.snapshot.Store(nextSnapshot)

	for {
		oldMetrics := cm.metrics.Load()
		nextMetrics := &ConfigMetrics{
			LastReloadTime: time.Now(),
			ReloadSuccess:  oldMetrics.ReloadSuccess + 1,
			ReloadFailure:  oldMetrics.ReloadFailure,
		}
		if cm.metrics.CompareAndSwap(oldMetrics, nextMetrics) {
			break
		}
	}

	return nil
}

func (cm *ConfigManager) GetMetrics() ConfigMetrics {
	return *cm.metrics.Load()
}

func (cm *ConfigManager) incrementFailureMetric() {
	for {
		oldMetrics := cm.metrics.Load()
		nextMetrics := &ConfigMetrics{
			LastReloadTime: oldMetrics.LastReloadTime,
			ReloadSuccess:  oldMetrics.ReloadSuccess,
			ReloadFailure:  oldMetrics.ReloadFailure + 1,
		}
		if cm.metrics.CompareAndSwap(oldMetrics, nextMetrics) {
			break
		}
	}
}

func validateRawConfig(raw rawMeshConfig) error {
	if strings.TrimSpace(raw.ActiveProfile) == "" {
		return fmt.Errorf("active profile name cannot be empty")
	}

	if _, exists := raw.Profiles[raw.ActiveProfile]; !exists {
		return fmt.Errorf("active profile '%s' is not defined in profiles map", raw.ActiveProfile)
	}

	type fieldConfig struct {
		name  string
		value float64
	}

	for name, prof := range raw.Profiles {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("found profile with an empty identifier")
		}

		fields := [4]fieldConfig{
			{name: "weight_loss", value: prof.WeightLoss},
			{name: "weight_ping", value: prof.WeightPing},
			{name: "weight_load", value: prof.WeightLoad},
			{name: "weight_power", value: prof.WeightPower},
		}

		var sum float64
		for _, f := range fields {
			if f.value < 0 {
				return fmt.Errorf("profile '%s' field '%s' cannot be negative (%f)", name, f.name, f.value)
			}
			if math.IsNaN(f.value) || math.IsInf(f.value, 0) {
				return fmt.Errorf("profile '%s' field '%s' has invalid float value (NaN/Inf)", name, f.name)
			}
			if f.value > maxWeight {
				return fmt.Errorf("profile '%s' field '%s' exceeds max allowed weight (%f)", name, f.name, maxWeight)
			}
			sum += f.value
		}

		if math.Abs(sum) < epsilon {
			return fmt.Errorf("profile '%s' cannot have all weights set to zero", name)
		}
	}
	return nil
}
