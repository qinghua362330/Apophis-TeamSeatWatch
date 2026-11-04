package browserenv

import (
	"encoding/json"
	"testing"
)

func TestDeployedBrowser156EnvironmentRemainsCompatible(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	e.RecipeVersion = "shardx-156.0.8078.48-linux-hd520-v1"
	if err := e.Validate(); err != nil {
		t.Fatalf("deployed browser version rejected: %v", err)
	}
	var recipe struct {
		Navigator struct {
			UserAgent string `json:"user_agent"`
		} `json:"navigator"`
		Hints struct {
			FullVersion string `json:"brand_full_version"`
		} `json:"client_hints"`
	}
	if err := json.Unmarshal(e.Recipe, &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.Navigator.UserAgent != UserAgent || recipe.Hints.FullVersion != "156.0.8078.48" {
		t.Fatal("browser recipe disagrees with deployed version")
	}
}
