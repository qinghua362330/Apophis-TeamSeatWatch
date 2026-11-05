package runtime

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/cpacred"
)

var errCPACredentialProxyUnavailable = errors.New("CPA credential proxy is unavailable")

type cpaProxySecret struct {
	version    int16
	nonce      []byte
	ciphertext []byte
}

// assignCPACredentialProxy chooses one currently usable, encrypted proxy and
// commits it into the CPA auth JSON. It deliberately has no direct fallback:
// callers that require proxy routing must fail closed when the pool is empty.
// The caller persists the returned credential in its sealed retry checkpoint.
func (h *OwnerAuthHandler) assignCPACredentialProxy(ctx context.Context, credential cpacred.Credential) (cpacred.Credential, error) {
	if h == nil || h.proxyPool == nil || h.proxyPool.pool == nil {
		return cpacred.Credential{}, errCPACredentialProxyUnavailable
	}
	rows, err := h.proxyPool.pool.Query(ctx, `
		SELECT n.endpoint_key_version,n.endpoint_nonce,n.endpoint_ciphertext
		FROM tsw_proxy_pool_nodes n
		LEFT JOIN tsw_proxy_pool_sources s ON s.id=n.source_id
		WHERE n.state='healthy' AND NOT n.retired
		  AND (n.stable_until IS NULL OR n.stable_until>now()+interval '2 minutes')
		  AND (n.source_id IS NULL OR s.enabled)
		ORDER BY n.id`)
	if err != nil {
		return cpacred.Credential{}, fmt.Errorf("list CPA credential proxies: %w", err)
	}
	defer rows.Close()
	var candidates []cpaProxySecret
	for rows.Next() {
		var candidate cpaProxySecret
		if err := rows.Scan(&candidate.version, &candidate.nonce, &candidate.ciphertext); err != nil {
			return cpacred.Credential{}, fmt.Errorf("read CPA credential proxy: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return cpacred.Credential{}, fmt.Errorf("read CPA credential proxies: %w", err)
	}
	if len(candidates) == 0 {
		return cpacred.Credential{}, errCPACredentialProxyUnavailable
	}
	index, err := chooseCPAProxyIndex(len(candidates), cryptorand.Reader)
	if err != nil {
		return cpacred.Credential{}, fmt.Errorf("choose CPA credential proxy: %w", err)
	}
	secret, err := auth.DecryptSecret(uint16(candidates[index].version), candidates[index].nonce, candidates[index].ciphertext, h.proxyPool.ring)
	if err != nil {
		return cpacred.Credential{}, fmt.Errorf("decrypt CPA credential proxy: %w", err)
	}
	updated, err := cpacred.WithProxy(credential, string(secret))
	if err != nil {
		return cpacred.Credential{}, fmt.Errorf("validate CPA credential proxy: %w", err)
	}
	return updated, nil
}

func chooseCPAProxyIndex(count int, random io.Reader) (int, error) {
	if count <= 0 {
		return 0, errCPACredentialProxyUnavailable
	}
	value, err := cryptorand.Int(random, big.NewInt(int64(count)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
