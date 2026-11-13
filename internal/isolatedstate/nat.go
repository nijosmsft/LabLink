package isolatedstate

import (
	"context"
	"database/sql"
)

func (s *Store) PutNAT(ctx context.Context, v NATAllocation) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nat_allocations(vm_id,orchestrator_id,state,conntrack_mark,updated_at_unix)
		VALUES(?,?,?,?,?)
		ON CONFLICT(vm_id) DO UPDATE SET state=excluded.state,
			conntrack_mark=excluded.conntrack_mark,updated_at_unix=excluded.updated_at_unix
	`, v.VMID, v.OrchestratorID, v.State, v.ConntrackMark, v.UpdatedAt)
	return err
}
func (s *Store) GetNAT(ctx context.Context, vmID string) (NATAllocation, error) {
	var v NATAllocation
	err := s.db.QueryRowContext(ctx, `
		SELECT vm_id,orchestrator_id,state,conntrack_mark,updated_at_unix
		FROM nat_allocations WHERE vm_id=?
	`, vmID).Scan(&v.VMID, &v.OrchestratorID, &v.State, &v.ConntrackMark, &v.UpdatedAt)
	return v, noRows("NAT", vmID, err)
}
func (s *Store) ListNAT(ctx context.Context, orchestratorID, networkID, state string) ([]NATAllocation, error) {
	query := `SELECT n.vm_id,n.orchestrator_id,n.state,n.conntrack_mark,n.updated_at_unix
		FROM nat_allocations n JOIN isolated_vms v ON v.id=n.vm_id WHERE 1=1`
	var args []any
	if orchestratorID != "" {
		query += ` AND n.orchestrator_id=?`
		args = append(args, orchestratorID)
	}
	if networkID != "" {
		query += ` AND v.network_id=?`
		args = append(args, networkID)
	}
	if state != "" {
		query += ` AND n.state=?`
		args = append(args, state)
	}
	query += ` ORDER BY n.vm_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []NATAllocation
	for rows.Next() {
		var v NATAllocation
		if err := rows.Scan(&v.VMID, &v.OrchestratorID,
			&v.State, &v.ConntrackMark, &v.UpdatedAt); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

var _ = sql.ErrNoRows
