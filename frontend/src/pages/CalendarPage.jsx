import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronLeft, ChevronRight, Calendar, AlertTriangle, Clock, FolderOpen } from 'lucide-react';
import { useTheme } from '../utils/theme';
import { casesAPI } from '../utils/api';

const PRIORITY_COLOR = {
  critical: 'var(--fl-danger)',
  high: 'var(--fl-warn)',
  medium: 'var(--fl-warn)',
  low: 'var(--fl-ok)',
};

function hoursLabel(h, t) {
  if (h < 0) return t('calendar.expired');
  if (h < 24) return `${Math.round(h)}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

export default function CalendarPage() {
  const { t, i18n } = useTranslation();
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
  const weekdayLabels = Array.from({ length: 7 }, (_, i) => {
    const base = new Date(Date.UTC(2024, 0, 1 + i));
    return new Intl.DateTimeFormat(i18n.language, { weekday: 'short' }).format(base);
  });
  const monthLabel = new Intl.DateTimeFormat(i18n.language, { month: 'long' }).format(new Date(viewYear, viewMonth, 1));

  return (
    <div className="p-6 max-w-6xl mx-auto" style={{ color: T.text }}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Calendar size={20} style={{ color: 'var(--fl-accent)' }} strokeWidth={1.6} />
          <h1 style={{ fontSize: 20, fontWeight: 600, fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em', margin: 0 }}>{t('calendar.title')}</h1>
        </div>
        <div className="text-sm" style={{ color: T.muted }}>
          {t('calendar.count', { count: deadlines.length })}
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
                {monthLabel} {viewYear}
              </span>
              <button onClick={nextMonth} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: T.dim }}>
                <ChevronRight size={18} />
              </button>
            </div>

            <div className="grid grid-cols-7 mb-1">
              {weekdayLabels.map(d => (
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
                      background: isToday ? `color-mix(in srgb, ${T.accent} 9%, transparent)` : dayDeadlines.length > 0 ? `${T.border}` : 'transparent',
                      border: isToday ? `1px solid color-mix(in srgb, ${T.accent} 38%, transparent)` : '1px solid transparent',
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
                          background: `color-mix(in srgb, ${PRIORITY_COLOR[dl.priority] || 'var(--fl-muted)'} 13%, transparent)`,
                          color: PRIORITY_COLOR[dl.priority] || T.dim,
                          fontSize: 10,
                        }}
                      >
                        {dl.case_number}
                      </button>
                    ))}
                    {hasUrgent && (
                      <div className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full" style={{ background: 'var(--fl-danger)' }} />
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
            <div className="rounded-xl p-4" style={{ background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)' }}>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={15} style={{ color: 'var(--fl-danger)' }} />
                <span className="font-semibold text-sm" style={{ color: 'var(--fl-danger)' }}>
                  {t('calendar.urgent', { count: urgent.length })}
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
                      <span className="text-xs font-semibold" style={{ color: 'var(--fl-danger)' }}>
                        {(() => {
                          const remaining = hoursLabel(d.hours_remaining, t);
                          return remaining === t('calendar.expired')
                            ? remaining
                            : t('calendar.hours_left', { value: remaining });
                        })()}
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
            <div className="rounded-xl p-4" style={{ background: 'color-mix(in srgb, var(--fl-warn) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-warn) 19%, transparent)' }}>
              <div className="flex items-center gap-2 mb-3">
                <Clock size={15} style={{ color: 'var(--fl-warn)' }} />
                <span className="font-semibold text-sm" style={{ color: 'var(--fl-warn)' }}>
                  {t('calendar.week', { count: upcoming.length })}
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
                      <span className="text-xs" style={{ color: 'var(--fl-warn)' }}>
                        {t('calendar.hours_left', { value: hoursLabel(d.hours_remaining, t) })}
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
              <span className="font-semibold text-sm" style={{ color: T.text }}>{t('calendar.all_deadlines')}</span>
            </div>
            {loading ? (
              <div className="text-xs" style={{ color: T.muted }}>{t('common.loading')}</div>
            ) : deadlines.length === 0 ? (
              <div className="text-xs" style={{ color: T.muted }}>{t('calendar.empty')}</div>
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
                    >
                      <span style={{ width: 7, height: 7, borderRadius: 2, background: PRIORITY_COLOR[d.priority] || 'var(--fl-subtle)', flexShrink: 0 }} />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium truncate" style={{ color: T.text }}>{d.title}</div>
                        <div className="text-xs" style={{ color: T.muted }}>
                          {dl.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' })}
                          {' · '}{d.case_number}
                        </div>
                      </div>
                      <div className="text-xs font-mono shrink-0" style={{
                        color: isUrgent ? 'var(--fl-danger)' : isWeek ? 'var(--fl-warn)' : T.muted,
                      }}>
                        {(() => {
                          const remaining = hoursLabel(d.hours_remaining, t);
                          return remaining === t('calendar.expired')
                            ? remaining
                            : t('calendar.hours_left', { value: remaining });
                        })()}
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
