-- ============================================================
-- Migration 001 — Index de performance Heimdall IR
-- Tous les index utilisent CONCURRENTLY pour ne pas bloquer
-- les lectures/écritures pendant la création.
-- Exécuter : psql -U forensiclab -d forensiclab -f 001_performance_indexes.sql
-- ============================================================

-- evidence : filtrage scan AV (quarantine dashboard, case detail)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_scan
  ON evidence(case_id, scan_status, scan_threat);

-- timeline_events : filtre par type (pivot forensique fréquent)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_timeline_events_type
  ON timeline_events(case_id, event_type);

-- timeline_events : lookup par evidence_id (drill-down preuve → événements)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_timeline_events_evidence
  ON timeline_events(evidence_id);

-- parser_results : lookup par parser_name (status panel, relance parsing)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_results_name
  ON parser_results(case_id, parser_name);

-- iocs : threat hunting — filtre is_malicious (dashboard KPI + hunting)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iocs_malicious
  ON iocs(case_id, is_malicious);

-- iocs : threat hunting — filtre sévérité décroissante
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iocs_severity
  ON iocs(case_id, severity DESC);

-- network_connections : analyse réseau — filtre protocole + suspicion
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_proto
  ON network_connections(case_id, protocol, is_suspicious);
