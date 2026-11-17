package postgres

import (
	"context"
	iq "github.com/StuHelper/stuhelper-information-query"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// Maintenance uses a separate pool with SELECT/DELETE only. Never mount it in HTTP.
// RetentionMonths defaults to 12 calendar months. Hosts configure approved retention.
type Maintenance struct {
	Pool            *pgxpool.Pool
	RetentionMonths int
	Now             func() time.Time
}

func (m Maintenance) PruneAudit(ctx context.Context, before time.Time, limit int) (int, error) {
	if m.Pool == nil {
		return 0, iq.ErrUnavailable
	}
	months := m.RetentionMonths
	if months == 0 {
		months = 12
	}
	if months < 1 || months > 1200 || limit < 1 || limit > 1000 || before.IsZero() {
		return 0, iq.ErrInvalid
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	if before.After(now.AddDate(0, -months, 0)) {
		return 0, iq.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err := m.Pool.Exec(ctx, `WITH expired AS (
 SELECT a.id FROM information_query.audit a
 WHERE a.created_at < $1
   AND NOT information_query.audit_is_held(
    a.id,
    COALESCE(a.body->>'request_id',''),
    CASE WHEN jsonb_typeof(a.body->'targets')='array' THEN a.body->'targets' ELSE '[]'::jsonb END
   )
 ORDER BY a.created_at,a.id LIMIT $2
 ) DELETE FROM information_query.audit a USING expired e WHERE a.id=e.id`, before, limit)
	if err != nil {
		return 0, err
	}
	return int(result.RowsAffected()), nil
}
