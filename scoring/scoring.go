package scoring

import (
	"encoding/json"
	"fmt"
	"os"

	"rzwinkels/elf_scanner/structs"
)

type Config struct {
	MaxScore   float64                  `json:"max_score"`
	Heuristics map[string]HeuristicRule `json:"heuristics"`
}

type HeuristicRule struct {
	Weight float64 `json:"weight"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Invert bool    `json:"invert"`
}

type Result struct {
	FileSHA256    string
	Path          string
	Name          string
	Score         float64
	MaxScore      float64
	Contributions []Contribution
}

type Contribution struct {
	ID     structs.HeuristicID
	Value  float64
	Score  float64
	Weight float64
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode scoring config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.MaxScore <= 0 {
		return fmt.Errorf("scoring config max_score must be greater than zero")
	}
	if len(config.Heuristics) == 0 {
		return fmt.Errorf("scoring config must define at least one heuristic")
	}
	for id, rule := range config.Heuristics {
		if rule.Weight < 0 {
			return fmt.Errorf("scoring rule %q has a negative weight", id)
		}
		if rule.Max <= rule.Min {
			return fmt.Errorf("scoring rule %q must have max greater than min", id)
		}
	}
	return nil
}

func Score(results structs.ELFHeuristicResults, config Config) (Result, error) {
	if err := config.Validate(); err != nil {
		return Result{}, err
	}

	score := Result{
		FileSHA256: results.FileSHA256,
		Path:       results.Path,
		Name:       results.Name,
		MaxScore:   config.MaxScore,
	}
	configuredWeight := 0.0
	for _, rule := range config.Heuristics {
		configuredWeight += rule.Weight
	}
	if configuredWeight == 0 {
		return score, nil
	}

	for _, heuristic := range results.Heuristics {
		if !heuristic.Evaluated {
			continue
		}
		rule, ok := config.Heuristics[string(heuristic.ID)]
		if !ok || rule.Weight == 0 {
			continue
		}

		normalized := (heuristic.Value - rule.Min) / (rule.Max - rule.Min)
		if rule.Invert {
			normalized = 1 - normalized
		}
		normalized = clamp(normalized, 0, 1)
		contribution := normalized * rule.Weight
		score.Score += contribution
		score.Contributions = append(score.Contributions, Contribution{
			ID:     heuristic.ID,
			Value:  heuristic.Value,
			Score:  contribution,
			Weight: rule.Weight,
		})
	}

	score.Score = score.Score / configuredWeight * config.MaxScore
	return score, nil
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
