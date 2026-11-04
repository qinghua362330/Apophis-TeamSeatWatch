// Package browserenv owns the one persisted browser identity shared by account uses.
package browserenv

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const Version = "shardx-156.0.8078.48-linux-hd520-v1"
const Executable = "/opt/shardx/chrome"
const ExecutableSHA256 = "5b1533db3b08c9cc8f7c24e0c2e31b6202d0bb1dad880f04978d03ce9e4b3ffa"
const UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
const AcceptLanguage = "en-US,en;q=0.9"

//go:embed recipe.json
var baseRecipe []byte

// Environment is explicit launch input, never inferred from credentials or context.
// RecipeVersion and Recipe pin the coherent native surfaces across service upgrades.
type Environment struct {
	ProfileID     uuid.UUID
	Seed          uint64
	DeviceID      string
	RecipeVersion string
	Recipe        json.RawMessage
}

func New() (Environment, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Environment{}, err
	}
	e := Environment{ProfileID: uuid.New(), Seed: binary.BigEndian.Uint64(seed[:]) & (1<<63 - 1), DeviceID: uuid.NewString(), RecipeVersion: Version}
	if e.Seed == 0 {
		e.Seed = 1
	}
	var err error
	e.Recipe, err = recipe(e.ProfileID, e.Seed)
	return e, err
}

func recipe(id uuid.UUID, seed uint64) ([]byte, error) {
	var r map[string]any
	if err := json.Unmarshal(baseRecipe, &r); err != nil {
		return nil, err
	}
	r["name"] = id.String()
	for slot, value := range r["noise"].(map[string]any) {
		h := fnv.New32a()
		fmt.Fprintf(h, "%s:%d::%s", id, seed, slot)
		value.(map[string]any)["seed"] = max(h.Sum32(), 1)
	}
	return json.Marshal(r)
}

func (e Environment) Validate() error {
	device, err := uuid.Parse(e.DeviceID)
	if e.ProfileID == uuid.Nil || e.Seed == 0 || err != nil || device == uuid.Nil || e.RecipeVersion != Version {
		return errors.New("account browser environment invalid")
	}
	expected, err := recipe(e.ProfileID, e.Seed)
	if err != nil {
		return err
	}
	// PostgreSQL jsonb normalizes formatting and key order.
	var actual any
	if json.Unmarshal(e.Recipe, &actual) != nil {
		return errors.New("account browser recipe invalid")
	}
	canonical, err := json.Marshal(actual)
	if err != nil || string(canonical) != string(expected) {
		return errors.New("account browser recipe changed; controlled upgrade required")
	}
	return nil
}

// Ensure is called inside the account's existing reservation transaction.
// A unique account key resolves first-assignment races without creating profiles eagerly.
func Ensure(ctx context.Context, tx pgx.Tx, kind string, account uuid.UUID) (Environment, error) {
	column := ""
	switch kind {
	case "mother":
		column = "mother_account_id"
	case "target":
		column = "target_account_id"
	default:
		return Environment{}, errors.New("browser account kind invalid")
	}
	e, err := New()
	if err != nil {
		return Environment{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tsw_account_browser_environments (`+column+`,profile_id,seed,device_id,recipe_version,recipe) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (`+column+`) DO NOTHING`, account, e.ProfileID, int64(e.Seed), e.DeviceID, e.RecipeVersion, []byte(e.Recipe))
	if err != nil {
		return Environment{}, err
	}
	err = tx.QueryRow(ctx, `SELECT profile_id,seed,device_id::text,recipe_version,recipe FROM tsw_account_browser_environments WHERE `+column+`=$1`, account).Scan(&e.ProfileID, &e.Seed, &e.DeviceID, &e.RecipeVersion, &e.Recipe)
	if err != nil {
		return Environment{}, err
	}
	return e, e.Validate()
}
