import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';

function countBy(records, key) {
  const map = new Map();
  records.forEach(r => {
    const v = r[key];
    if (v) map.set(v, (map.get(v) || 0) + 1);
  });
  return [...map.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count);
}

function EntitySection({ title, items, onSelect, activeValue }) {
  const [open, setOpen] = useState(true);
  if (!items.length) return null;
  return (
    <div style={{ marginBottom: 2 }}>
      <div onClick={() => setOpen(v => !v)}
        style={{ padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
        {open
          ? <ChevronDown  size={9} style={{ color: 'var(--fl-muted)' }} />
          : <ChevronRight size={9} style={{ color: 'var(--fl-muted)' }} />}
        <span style={{ flex: 1, fontSize: 8, fontWeight: 700, letterSpacing: '0.14em',
          textTransform: 'uppercase', color: 'var(--fl-subtle)' }}>{title}</span>
        <span style={{ fontSize: 8, color: 'var(--fl-raised)' }}>{items.length}</span>
      </div>
      {open && items.map(({ value, count }) => {
        const active = activeValue === value;
        return (
          <div key={value} onClick={() => onSelect(value)}
            style={{ padding: '3px 10px 3px 22px', display: 'flex', alignItems: 'center', gap: 6,
              cursor: 'pointer',
              borderLeft: active ? '2px solid var(--fl-accent)' : '2px solid transparent',
              background: active ? 'var(--fl-card)' : 'transparent' }}
            onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--fl-panel)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = active ? 'var(--fl-card)' : 'transparent'; }}>
            <span style={{ flex: 1, fontSize: 10,
              color: active ? 'var(--fl-accent)' : '#6a8ab0',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {value}
            </span>
            <span style={{ fontSize: 9, color: 'var(--fl-muted)' }}>{count.toLocaleString()}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function EntitiesTab() {
  const { records, hostsAvail, usersAvail, hostFilter, userFilter, search,
          setFilter, applyFilters } = useTimelineStore();

  const hosts = useMemo(() => {
    if (hostsAvail.length) {
      return hostsAvail
        .map(h => ({ value: h, count: records.filter(r => r.host_name === h).length }))
        .filter(x => x.count > 0);
    }
    return countBy(records, 'host_name');
  }, [records, hostsAvail]);

  const users = useMemo(() => {
    if (usersAvail.length) {
      return usersAvail
        .map(u => ({ value: u, count: records.filter(r => r.user_name === u).length }))
        .filter(x => x.count > 0);
    }
    return countBy(records, 'user_name');
  }, [records, usersAvail]);

  const EXEC_RE = /\.(exe|dll|sys|com|bat|cmd|ps1|msi|py|sh|vbs|jar|appx|apk|bin)$/i;
  const processes = useMemo(() => {
    // Extraire le nom de fichier seul (strip \Device\HarddiskVolume3\...\foo.exe → foo.exe)
    const map = new Map();
    records.forEach(r => {
      if (!r.process_name) return;
      const name = String(r.process_name).split(/[/\\]/).pop() || '';
      if (!name || !EXEC_RE.test(name)) return;
      map.set(name.toUpperCase(), (map.get(name.toUpperCase()) || 0) + 1);
    });
    return [...map.entries()]
      .map(([value, count]) => ({ value, count }))
      .sort((a, b) => a.value.localeCompare(b.value));
  }, [records]);

  function selectHost(v) {
    setFilter('hostFilter', hostFilter === v ? '' : v);
    applyFilters();
  }

  function selectUser(v) {
    setFilter('userFilter', userFilter === v ? '' : v);
    applyFilters();
  }

  function selectProcess(v) {
    setFilter('search', search === v ? '' : v);
    applyFilters();
  }

  if (!records.length) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--fl-subtle)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: 16, textAlign: 'center' }}>
        No events loaded
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto' }}>
      <EntitySection title="Hosts"     items={hosts}     activeValue={hostFilter} onSelect={selectHost}    />
      <EntitySection title="Users"     items={users}     activeValue={userFilter} onSelect={selectUser}    />
      <EntitySection title="Processes" items={processes} activeValue={search}     onSelect={selectProcess} />
    </div>
  );
}
