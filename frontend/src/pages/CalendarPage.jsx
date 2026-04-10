import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Calendar, AlertTriangle, Clock, FolderOpen } from 'lucide-react';
import { useTheme } from '../utils/theme';
import { casesAPI } from '../utils/api';

const PRIORITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const WEEKDAYS = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];
const MONTHS = [
  'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
  'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre',
];

function hoursLabel(h) {
  if (h < 0) return 'Expiré';
  if (h < 24) return `${Math.round(h)}h restantes`;
  const d = Math.floor(h / 24);
  return `${d}j restants`;
}

export default function CalendarPage() {
  const T = useTheme();
  const navigate = useNavigate();
  const [deadlines, setDeadlines] = useState([]);
  const [loading, setLoading] = useState(true);
  const today = new Date();
  const [viewYear, setViewYear] = useState(today.getFullYear());
  const [viewMonth, setViewMonth] = useState(today.getMonth());

  useEffect(() => {
    casesAPI.deadlines()
      .then(r => setDeadlines(r.data.deadlines || []))
      .catch(() => setDeadlines([]))
      .finally(() => setLoading(false));
  }, []);

  const byDay = {};
  deadlines.forEach(d => {
    const key = d.report_deadline.slice(0, 10);
    if (!byDay[key]) byDay[key] = [];
    byDay[key].push(d);
  });

  const firstDay = new Date(viewYear, viewMonth, 1);
  let startDow = firstDay.getDay();
  startDow = startDow === 0 ? 6 : startDow - 1;
  const daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
  const cells = [];
  for (let i = 0; i < startDow; i++) cells.push(null);
  for (let d = 1; d <= daysInMonth; d++) cells.push(d);

  function prevMonth() {
    if (viewMonth === 0) { setViewMonth(11); setViewYear(y => y - 1); }
    else setViewMonth(m => m - 1);
  }
  function nextMonth() {
    if (viewMonth === 11) { setViewMonth(0); setViewYear(y => y + 1); }
    else setViewMonth(m => m + 1);
  }

  const urgent = deadlines.filter(d => d.hours_remaining != null && d.hours_remaining < 48);
  const upcoming = deadlines.filter(d => d.hours_remaining != null && d.hours_remaining >= 48 && d.hours_remaining < 168);

  return (
    <div className="p-6 max-w-6xl mx-auto" style={{ color: T.text }}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Calendar size={22} style={{ color: T.accent }} />
          <h1 className="text-xl font-semibold">Calendrier des Échéances</h1>
        </div>
        <div className="text-sm" style={{ color: T.muted }}>
          {deadlines.length} échéance{deadlines.length !== 1 ? 's' : ''} dans les 60 prochains jours
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="rounded-xl p-5" style={{ background: T.panel, border: `1px solid ${T.border}` }}>
            <div className="flex items-center justify-between mb-4">
              <button onClick={prevMonth} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: T.dim }}>
                <ChevronLeft size={18} />
              </button>
              <span className="font-semibold text-base">
                {MONTHS[viewMonth]} {viewYear}
              </span>
              <button onClick={nextMonth} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: T.dim }}>
                <ChevronRight size={18} />
              </button>
            </div>

            <div className="grid grid-cols-7 mb-1">
              {WEEKDAYS.map(d => (
                <div key={d} className="text-center text-xs font-medium py-1" style={{ color: T.muted }}>{d}</div>
              ))}
            </div>

            <div className="grid grid-cols-7 gap-1">
              {cells.map((day, i) => {
                if (!day) return <div key={`empty-${i}`} />;
                const dateStr = `${viewYear}-${String(viewMonth + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
                const dayDeadlines = byDay[dateStr] || [];
                const isToday = (
                  day === today.getDate() &&
                  viewMonth === today.getMonth() &&
                  viewYear === today.getFullYear()
                );
                const hasUrgent = dayDeadlines.some(d => d.hours_remaining < 48);
                const hasMedium = dayDeadlines.some(d => d.hours_remaining >= 48 && d.hours_remaining < 168);

                return (
                  <div
                    key={dateStr}
                    className="relative rounded-lg p-1.5 min-h-14"
                    style={{
                      background: isToday ? `${T.accent}18` : dayDeadlines.length > 0 ? `${T.border}` : 'transparent',
                      border: isToday ? `1px solid ${T.accent}60` : '1px solid transparent',
                    }}
                  >
                    <div className="text-xs font-medium mb-1" style={{
                      color: isToday ? T.accent : T.dim,
                      fontWeight: isToday ? 700 : 400,
                    }}>{day}</div>
                    {dayDeadlines.map((dl, idx) => (
                      <button
                        key={dl.id}
                        onClick={() => navigate(`/cases/${dl.id}`)}
                        className="w-full text-left text-xs rounded px-1 py-0.5 mb-0.5 truncate"
                        title={dl.title}
                        style={{
                          background: `${PRIORITY_COLOR[dl.priority] || '#6b7280'}22`,
                          color: PRIORITY_COLOR[dl.priority] || T.dim,
                          fontSize: 10,
                        }}
                      >
                        {dl.case_number}
                      </button>
                    ))}
                    {hasUrgent && (
                      <div className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full" style={{ background: '#ef4444' }} />
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex items-center gap-4 mt-4 pt-3" style={{ borderTop: `1px solid ${T.border}` }}>
              {Object.entries(PRIORITY_COLOR).map(([p, c]) => (
                <div key={p} className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-sm" style={{ background: c }} />
                  <span className="text-xs capitalize" style={{ color: T.muted }}>{p}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {urgent.length > 0 && (
            <div className="rounded-xl p-4" style={{ background: '#ef444410', border: '1px solid #ef444430' }}>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={15} style={{ color: '#ef4444' }} />
                <span className="font-semibold text-sm" style={{ color: '#ef4444' }}>
                  Urgents — &lt; 48h ({urgent.length})
                </span>
              </div>
              <div className="space-y-2">
                {urgent.map(d => (
                  <button
                    key={d.id}
                    onClick={() => navigate(`/cases/${d.id}`)}
                    className="w-full text-left rounded-lg p-2.5 transition-opacity hover:opacity-80"
                    style={{ background: T.panel, border: `1px solid ${T.border}` }}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="font-mono text-xs" style={{ color: T.accent }}>{d.case_number}</span>
                      <span className="text-xs font-semibold" style={{ color: '#ef4444' }}>
                        {hoursLabel(d.hours_remaining)}
                      </span>
                    </div>
                    <div className="text-xs font-medium truncate" style={{ color: T.text }}>{d.title}</div>
                    {d.investigator_name && (
                      <div className="text-xs mt-0.5" style={{ color: T.muted }}>{d.investigator_name}</div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {upcoming.length > 0 && (
            <div className="rounded-xl p-4" style={{ background: '#f9731610', border: '1px solid #f9731630' }}>
              <div className="flex items-center gap-2 mb-3">
                <Clock size={15} style={{ color: '#f97316' }} />
                <span className="font-semibold text-sm" style={{ color: '#f97316' }}>
                  Cette semaine ({upcoming.length})
                </span>
              </div>
              <div className="space-y-2">
                {upcoming.map(d => (
                  <button
                    key={d.id}
                    onClick={() => navigate(`/cases/${d.id}`)}
                    className="w-full text-left rounded-lg p-2.5 transition-opacity hover:opacity-80"
                    style={{ background: T.panel, border: `1px solid ${T.border}` }}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="font-mono text-xs" style={{ color: T.accent }}>{d.case_number}</span>
                      <span className="text-xs" style={{ color: '#f97316' }}>
                        {hoursLabel(d.hours_remaining)}
                      </span>
                    </div>
                    <div className="text-xs font-medium truncate" style={{ color: T.text }}>{d.title}</div>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-xl p-4" style={{ background: T.panel, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-2 mb-3">
              <FolderOpen size={15} style={{ color: T.dim }} />
              <span className="font-semibold text-sm" style={{ color: T.text }}>Toutes les échéances</span>
            </div>
            {loading ? (
              <div className="text-xs" style={{ color: T.muted }}>Chargement…</div>
            ) : deadlines.length === 0 ? (
              <div className="text-xs" style={{ color: T.muted }}>Aucune échéance planifiée</div>
            ) : (
              <div className="space-y-1.5 max-h-80 overflow-y-auto">
                {deadlines.map(d => {
                  const dl = new Date(d.report_deadline);
                  const isUrgent = d.hours_remaining < 48;
                  const isWeek = d.hours_remaining >= 48 && d.hours_remaining < 168;
                  return (
                    <button
                      key={d.id}
                      onClick={() => navigate(`/cases/${d.id}`)}
                      className="w-full text-left flex items-center gap-2 px-2 py-1.5 rounded-md transition-opacity hover:opacity-70"
                      style={{ borderLeft: `2px solid ${PRIORITY_COLOR[d.priority] || T.border}` }}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium truncate" style={{ color: T.text }}>{d.title}</div>
                        <div className="text-xs" style={{ color: T.muted }}>
                          {dl.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' })}
                          {' · '}{d.case_number}
                        </div>
                      </div>
                      <div className="text-xs font-mono shrink-0" style={{
                        color: isUrgent ? '#ef4444' : isWeek ? '#f97316' : T.muted,
                      }}>
                        {hoursLabel(d.hours_remaining)}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
