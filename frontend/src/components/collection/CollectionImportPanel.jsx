import { useState, useEffect, useRef, useReducer } from 'react';
import { useTranslation } from 'react-i18next';
import { useSocket } from '../../hooks/useSocket';
import { CheckCircle2, Loader2, Package, Cpu, AlertTriangle, X, Terminal, Network, Lock, Clock, HardDrive, Server, Copy } from 'lucide-react';
import { collectionAPI, threatHuntingAPI } from '../../utils/api';
import { zipSync } from 'fflate';
import { markStyle } from '../ui/tableIdiom';
import { probeFile } from '../../utils/fileProbe';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { artefactsTries, typesAbsents, mesureDEtape, etatsApresEvenement, etapesDeChaine, etatsDeChaine, indexDEtape, hayabusaDepuisChasse } from './importView';
import { avancement, parseurPrincipal } from './parsingView';
import { fmtOctets } from './octets';
import { classerDepot } from './importQueue';
import { entreesInitiales, fileApres, aLancer, ligneDeChaine, resteAvantLancement } from './multiImport';
import { replier, enfantsAffiches, etatCase, typesSous, vueDeDepart } from './arbreVue';
import { ligneNavigateur } from './journalVue';
import ParseTerminal from './ParseTerminal';
import ParseursDepliant from './ParseursDepliant';

const FS_MARK_SM = 9;
const HAYABUSA_VIDE = { statut: 'attente', detections: null, erreur: null };
const reduireMulti = (etat, ev) => (ev.type === 'init' ? entreesInitiales(ev.entrees) : ev.type === 'vider' ? null : fileApres(etat, ev));
const MARK_ROW = { display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'baseline' };

const ROLLUP_STATUS_META = {
  queued:  { labelKey: 'collection.pm_queued',  color: 'var(--fl-muted)' },
  parsing: { labelKey: 'collection.pm_parsing', color: 'var(--fl-accent)' },
  done:    { labelKey: 'collection.pm_done',    color: 'var(--fl-ok)' },
  skipped: { labelKey: 'collection.pm_skipped', color: 'var(--fl-artifact-registry)' },
  error:   { labelKey: 'collection.pm_error',   color: 'var(--fl-danger)' },
};
const ROLLUP_STATUS_ORDER = ['error', 'skipped', 'parsing', 'queued', 'done'];

function rollupParserStates(parserStates) {
  const counts = {};
  for (const state of Object.values(parserStates || {})) {
    const status = state?.status || 'queued';
    counts[status] = (counts[status] || 0) + 1;
  }
  return counts;
}

function StatusRollup({ parserStates, t, style }) {
  const counts = rollupParserStates(parserStates);
  if (Object.keys(parserStates || {}).length === 0) return null;
  return (
    <div style={{ ...MARK_ROW, ...style }}>
      {ROLLUP_STATUS_ORDER.map(status => {
        const count = counts[status] || 0;
        if (count === 0) return null;
        const meta = ROLLUP_STATUS_META[status];
        return (
          <span key={status} style={markStyle(meta.color)}>
            {count} {t(meta.labelKey)}
          </span>
        );
      })}
    </div>
  );
}

async function collectEntries(entry, prefix = '') {
  if (entry.isFile) {
    return new Promise((resolve) => {
      entry.file(f => resolve([{ file: f, path: prefix + f.name }]), () => resolve([]));
    });
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const all = [];
    while (true) {
      const batch = await new Promise((resolve) => reader.readEntries(resolve, () => resolve([])));
      if (!batch.length) break;
      for (const child of batch) {
        const sub = await collectEntries(child, prefix + entry.name + '/');
        all.push(...sub);
      }
    }
    return all;
  }
  return [];
}

async function zipperFichiers(fichiers) {
  const carte = {};
  await Promise.all(fichiers.map(f => f.arrayBuffer().then(buf => { carte[f.name] = new Uint8Array(buf); })));
  return new File([zipSync(carte, { level: 0 })], 'artifacts.zip', { type: 'application/zip' });
}

async function buildZipFromItems(dataTransferItems) {
  const allFiles = [];
  for (const item of dataTransferItems) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) {
      const collected = await collectEntries(entry);
      allFiles.push(...collected);
    }
  }
  if (allFiles.length === 0) return null;

  const fileMap = {};
  await Promise.all(allFiles.map(({ file, path }) =>
    file.arrayBuffer().then(buf => { fileMap[path] = new Uint8Array(buf); })
  ));
  const zipped = zipSync(fileMap, { level: 0 });
  return new File([zipped], 'artifacts.zip', { type: 'application/zip' });
}

const ARTIFACTS = {
  evtx:      { name: 'Event Logs (EVTX)', color: 'var(--fl-artifact-evtx)',      parser: 'EvtxECmd',       platform: 'windows' },
  prefetch:  { name: 'Prefetch',          color: 'var(--fl-artifact-prefetch)',  parser: 'PECmd',           platform: 'windows' },
  mft:       { name: '$MFT',              color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  usn:       { name: '$J (USN Journal)',  color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  indx:      { name: '$I30 (INDX)',       color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  lnk:       { name: 'LNK Shortcuts',     color: 'var(--fl-artifact-lnk)',       parser: 'LECmd',           platform: 'windows' },
  registry:  { name: 'Registry Hives',    color: 'var(--fl-artifact-registry)',  parser: 'RECmd',           platform: 'windows' },
  userassist:{ name: 'UserAssist',        color: 'var(--fl-artifact-registry)',  parser: 'dissect.regf',    platform: 'windows' },
  netprofile:{ name: 'Network Profiles',  color: 'var(--fl-artifact-registry)',  parser: 'dissect.regf',    platform: 'windows', labelKey: 'collection.import.artifacts.netprofile' },
  usb:       { name: 'USB History',       color: 'var(--fl-artifact-recycle)',   parser: 'setupapi.dev.log',platform: 'windows', labelKey: 'collection.import.artifacts.usb' },
  schtasks:  { name: 'Scheduled Tasks',   color: 'var(--fl-artifact-registry)',  parser: 'XML',             platform: 'windows', labelKey: 'collection.import.artifacts.schtasks' },
  pwsh:      { name: 'PowerShell History',color: 'var(--fl-artifact-evtx)',      parser: 'PSReadLine',      platform: 'windows' },
  dns:       { name: 'DNS / hosts',       color: 'var(--fl-artifact-srum)',      parser: 'text',            platform: 'windows' },
  webcache:  { name: 'WebCache (IE/Edge)', color: 'var(--fl-artifact-sqle)',      parser: 'dissect.esedb',   platform: 'windows' },
  pcap:      { name: 'Network Capture (PCAP)', color: 'var(--fl-ok)',             parser: 'tshark',          platform: 'windows', labelKey: 'collection.import.artifacts.pcap' },
  wmi:       { name: 'WMI Persistence', color: 'var(--fl-artifact-registry)',  parser: 'dissect.cim',     platform: 'windows', labelKey: 'collection.import.artifacts.wmi' },
  rdpcache:  { name: 'RDP Bitmap Cache', color: 'var(--fl-artifact-lnk)',       parser: 'bmc-tools',       platform: 'windows' },
  amcache:   { name: 'Amcache',           color: 'var(--fl-artifact-amcache)',   parser: 'AmcacheParser',   platform: 'windows' },
  shellbags: { name: 'Shellbags',         color: 'var(--fl-artifact-shellbags)', parser: 'SBECmd',          platform: 'windows' },
  jumplist:  { name: 'Jump Lists',        color: 'var(--fl-artifact-jumplist)',  parser: 'JLECmd',          platform: 'windows' },
  srum:      { name: 'SRUM',              color: 'var(--fl-artifact-srum)',      parser: 'SrumECmd',        platform: 'windows' },
  recycle:   { name: 'Recycle Bin',       color: 'var(--fl-artifact-recycle)',   parser: 'RBCmd',           platform: 'windows' },
  sum:       { name: 'Browser SQLite',    color: 'var(--fl-artifact-sqle)',      parser: 'SQLECmd',         platform: 'windows' },
  sqle:      { name: 'SQLite DBs',        color: 'var(--fl-artifact-sqle)',      parser: 'SQLECmd',         platform: 'windows' },
  wxtcmd:    { name: 'WER / WxTCmd',      color: 'var(--fl-artifact-wer)',       parser: 'WxTCmd',          platform: 'windows' },
  appcompat: { name: 'AppCompat Cache',   color: 'var(--fl-artifact-appcompat)', parser: 'AppCompatParser', platform: 'windows' },
  bits:      { name: 'BITS Jobs',         color: 'var(--fl-artifact-bits)',      parser: 'BitsParser',      platform: 'windows' },
  catscale:  { name: 'CatScale Linux IR', color: 'var(--fl-artifact-catscale)',  parser: 'CatScale',        platform: 'linux'   },
  auditd:    { name: 'Linux Auditd',      color: 'var(--fl-artifact-catscale)',  parser: 'parse_auditd.py', platform: 'linux',   labelKey: 'collection.import.artifacts.auditd' },
  syslog:    { name: 'Linux Syslog',      color: 'var(--fl-artifact-catscale)',  parser: 'parse_syslog.py', platform: 'linux',   labelKey: 'collection.import.artifacts.syslog' },
  bash_history: { name: 'Bash/Zsh History', color: 'var(--fl-artifact-evtx)',   parser: 'parse_bash_history.py', platform: 'linux', labelKey: 'collection.import.artifacts.bash_history' },
  unified_log: { name: 'macOS Unified Log', color: 'var(--fl-artifact-amcache)', parser: 'parse_unified_log.py', platform: 'macos', labelKey: 'collection.import.artifacts.unified_log' },
};

const CATSCALE_STEPS = {
  auth_logs:    { label: 'auth.log / secure / syslog',      icon: Lock },
  logon_history:{ labelKey: 'collection.import.catscale_steps.logon_history', icon: Server },
  processes:    { labelKey: 'collection.import.catscale_steps.processes', icon: Cpu },
  network:      { labelKey: 'collection.import.catscale_steps.network', icon: Network },
  history:      { labelKey: 'collection.import.catscale_steps.history', icon: Terminal },
  persistence:  { labelKey: 'collection.import.catscale_steps.persistence', icon: Clock },
  filesystem:   { label: 'Timeline filesystem',              icon: HardDrive },
};

function parseCatScaleArtifact(raw) {
  const m = /^(\w+):(.+?)\s*\((\d+)\)$/.exec(raw.trim());
  if (!m) return { type: raw, label: raw, count: 0 };
  return { type: m[1], label: m[2], count: parseInt(m[3], 10) };
}

const CATSCALE_TYPE_COLORS = {
  auth:         'var(--fl-danger)',
  failed_logon: 'var(--fl-warn)',
  logon:        'var(--fl-gold)',
  process:      'var(--fl-accent)',
  network:      'var(--fl-ok)',
  history:      'var(--fl-accent)',
  cron:         'var(--fl-purple)',
  systemd:      'var(--fl-purple)',
  fstimeline:   'var(--fl-muted)',
};

export default function CollectionImportPanel({ caseId, caseObj, onDone, socketAffaire }) {
  const { t, i18n } = useTranslation();
  const { socket, socketId } = useSocket();
  const fileRef = useRef(null);
  const compteurNav = useRef(0);

  const [step,            setStep]            = useState('idle');
  const [octets,          setOctets]          = useState({ recus: 0, total: 0 });
  const [fileAttente,     setFileAttente]     = useState([]);
  const [arbre,           setArbre]           = useState(null);
  const [pile,            setPile]            = useState([]);
  const [empreinteA,      setEmpreinteA]      = useState(() => Date.now());
  const [releve,          setReleve]          = useState(() => Date.now());
  const [detected,        setDetected]        = useState(null);
  const [selected,        setSelected]        = useState([]);
  const [optionsMft,      setOptionsMft]      = useState({ recover_slack: false, include_resident_data: false });
  const [results,         setResults]         = useState(null);
  const [debutParsing,    setDebutParsing]    = useState(null);
  const [hayabusa,        setHayabusa]        = useState(HAYABUSA_VIDE);
  const [echecEtape,      setEchecEtape]      = useState(null);
  const stepRef = useRef('idle');
  const [multi, envoyerMulti] = useReducer(reduireMulti, null);
  const multiRef = useRef(null);
  const [fileHashes,      setFileHashes]      = useState(null);
  const [error,           setError]           = useState('');
  const [fileName,        setFileName]        = useState('');
  const [collDir,         setCollDir]         = useState('');
  const [pipelineLog,     setPipelineLog]     = useState([]);
  const [requeteJournal,  setRequeteJournal]  = useState('');
  const [dragging,        setDragging]        = useState(false);
  const [copiedHash,      setCopiedHash]      = useState(null);
  const [catscaleDetail,  setCatscaleDetail]  = useState(null);
  const [catscaleStep,    setCatscaleStep]    = useState(null);
  const [parserStates,    setParserStates]    = useState({});
  const locale = i18n.language === 'fr' ? 'fr-FR' : 'en-US';
  const artifactLabel = (type) => {
    const artifact = ARTIFACTS[type];
    return artifact?.labelKey ? t(artifact.labelKey) : artifact?.name || type;
  };
  const catscaleStepLabel = (key) => {
    const stepMeta = CATSCALE_STEPS[key];
    return stepMeta?.labelKey ? t(stepMeta.labelKey) : stepMeta?.label || key;
  };

  useEffect(() => { stepRef.current = step; }, [step]);
  useEffect(() => {
    if (step !== 'hayabusa' || !caseId) return;
    let vivant = true;
    const sonder = () => threatHuntingAPI.runAllStatus(caseId)
      .then(r => {
        if (!vivant) return;
        const h = hayabusaDepuisChasse(r.data, debutParsing);
        setHayabusa(h);
        if (h.statut === 'fait') {
          addLog(t('collection.import.log.hayabusa_done', { count: (h.detections ?? 0).toLocaleString(locale) }), 'ok');
        } else if (h.statut === 'erreur') {
          addLog(t('collection.import.log.hayabusa_error', { error: h.erreur || t('collection.import.errors.unavailable') }), 'erreur');
        }
        if (h.statut === 'fait' || h.statut === 'erreur') {
          setStep('done');
          addLog(t('collection.import.log.pipeline_done'));
          onDone?.();
        }
      })
      .catch(() => {});
    sonder();
    const iv = setInterval(sonder, 3000);
    return () => { vivant = false; clearInterval(iv); };
  }, [step, caseId, debutParsing]);
  useEffect(() => { setReleve(Date.now()); }, [step, pipelineLog.length, parserStates]);
  useEffect(() => { if (fileHashes && (fileHashes.md5 || fileHashes.sha256)) setEmpreinteA(Date.now()); }, [fileHashes]);
  useEffect(() => { multiRef.current = multi; }, [multi]);
  const [maintenant, setMaintenant] = useState(() => Date.now());
  const multiAttend = Array.isArray(multi) && multi.some(e => e.etat === 'detecte' && !e.lance);
  useEffect(() => {
    if (!multiAttend) return;
    const iv = setInterval(() => setMaintenant(Date.now()), 1000);
    return () => clearInterval(iv);
  }, [multiAttend]);
  useEffect(() => {
    if (!Array.isArray(multi) || !caseId) return;
    for (const e of aLancer(multi, Date.now())) {
      envoyerMulti({ type: 'lance', collDir: e.collDir });
      collectionAPI.parse(caseId, { collection_dir: e.collDir, artifact_types: e.catscale ? 'all' : e.retenus, socketId: socket?.id || null })
        .catch(err => envoyerMulti({ type: 'erreur', collDir: e.collDir, message: err.response?.data?.error || err.message }));
    }
  }, [multi, maintenant, caseId, socket]);
  const multiEnHayabusa = Array.isArray(multi) && multi.some(e => e.etat === 'hayabusa');
  useEffect(() => {
    if (!multiEnHayabusa || !caseId) return;
    let vivant = true;
    const sonder = () => threatHuntingAPI.runAllStatus(caseId)
      .then(r => { if (vivant) envoyerMulti({ type: 'chasse', chasse: r.data }); })
      .catch(() => {});
    sonder();
    const iv = setInterval(sonder, 3000);
    return () => { vivant = false; clearInterval(iv); };
  }, [multiEnHayabusa, caseId]);
  const multiTermine = Array.isArray(multi) && multi.length > 0 && multi.every(e => e.etat === 'fini' || e.etat === 'erreur');
  const multiEnCours = Array.isArray(multi) && !multiTermine;
  useEffect(() => { if (multiTermine) onDone?.(); }, [multiTermine]);

  const keyFromEventName = (name) => {
    if (!name) return null;
    const n = String(name).toLowerCase();
    return Object.keys(ARTIFACTS).find(k =>
      n.includes(k) ||
      n.includes(String(artifactLabel(k)).toLowerCase()) ||
      n.includes(String(ARTIFACTS[k].parser).toLowerCase())
    ) || null;
  };

  useEffect(() => {
    if (!socket) return;
    function handleProgress(data) {
      if (Array.isArray(multiRef.current)) return;
      if (data.type === 'start') {
        setParserStates(p => etatsApresEvenement(p, data, null));
      } else if (data.type === 'artifact_start') {
        const _k = data.artifact || keyFromEventName(data.name);
        setParserStates(p => etatsApresEvenement(p, data, _k));
      } else if (data.type === 'artifact_done') {
        if (data.status === 'error')
          addLog(t('collection.import.log.artifact_error', { name: data.name }), 'erreur');
        const _kd = data.artifact || keyFromEventName(data.name);
        setParserStates(p => etatsApresEvenement(p, data, _kd));
      } else if (data.type === 'catscale_step') {
        const info = CATSCALE_STEPS[data.step];
        setCatscaleStep(data.step);
        if (info) addLog(t('collection.import.log.catscale_step', { label: catscaleStepLabel(data.step) }), 'etape');
      } else if (data.type === 'saving') {
        addLog(t('collection.import.log.saving'));
      }
    }
    socket.on('collection:progress', handleProgress);
    return () => socket.off('collection:progress', handleProgress);
  }, [socket, t, locale]);

  useEffect(() => {
    if (!socket) return;
    const actif = () => Array.isArray(multiRef.current);
    const surExtrait = (d) => { if (actif()) envoyerMulti({ type: 'extrait', collDir: d?.collection_dir, detected: d?.detected_artifacts, arbre: d?.arbre, maintenant: Date.now() }); };
    const surErreurImport = (d) => { if (actif() && d?.collection_dir) envoyerMulti({ type: 'erreur', collDir: d.collection_dir, message: d?.details || d?.error }); };
    const surProgression = (d) => { if (actif()) envoyerMulti({ type: 'progression', data: { ...d, artifact: d?.artifact || keyFromEventName(d?.name) } }); };
    const surParseFini = (d) => { if (actif()) envoyerMulti({ type: 'parse_fini', collDir: d?.collection_dir, started_at: d?.started_at }); };
    const surErreurParse = (d) => { if (actif() && d?.collection_dir) envoyerMulti({ type: 'erreur', collDir: d.collection_dir, message: d?.details || d?.error }); };
    socket.on('collection:import:done', surExtrait);
    socket.on('collection:import:error', surErreurImport);
    socket.on('collection:progress', surProgression);
    socket.on('collection:parse:done', surParseFini);
    socket.on('collection:parse:error', surErreurParse);
    return () => {
      socket.off('collection:import:done', surExtrait);
      socket.off('collection:import:error', surErreurImport);
      socket.off('collection:progress', surProgression);
      socket.off('collection:parse:done', surParseFini);
      socket.off('collection:parse:error', surErreurParse);
    };
  }, [socket]);

  const envoyerPreuve = async (entree, id) => {
    try {
      const fichier = entree.mode === 'paquet' ? await zipperFichiers(entree.fichiers) : entree.fichiers[0];
      const probe = await probeFile(fichier);
      if (!probe.readable) {
        throw new Error(probe.reason === 'empty'
          ? t('collection.import.errors.file_empty', { name: fichier.name })
          : t('collection.import.errors.file_unreadable', { name: fichier.name }));
      }
      const formData = new FormData();
      formData.append('collection', fichier);
      formData.append('socketId', socket?.id || '');
      envoyerMulti({ type: 'envoi', id, recus: 0, total: fichier.size });
      const res = await collectionAPI.import(caseId, formData, (e) => {
        envoyerMulti({ type: 'envoi', id, recus: e.loaded || 0, total: e.total || fichier.size });
      });
      envoyerMulti({ type: 'envoye', id, collDir: res.data?.collection_dir || null });
    } catch (err) {
      const brut = err.response?.data?.error;
      envoyerMulti({ type: 'erreur', id, message: (typeof brut === 'string' ? brut : brut?.message) || err.message });
    }
  };

  const addLog = (msg, niveau = 'info') => setPipelineLog(prev => [...prev, ligneNavigateur(msg, niveau, new Date(), ++compteurNav.current)]);

  const accueillirDepot = async (fichiers) => {
    const { entrees, refuses } = classerDepot(fichiers);
    for (const r of refuses) {
      addLog(t('collection.import.log.refused', {
        name: r.nom,
        motif: t(`collection.import.refus_${r.motif}`),
      }), 'ignore');
    }
    if (entrees.length === 0) {
      if (refuses.length > 0) setError(t('collection.import.errors.no_file_to_archive'));
      return;
    }
    if (entrees.length >= 2) {
      if (!socket) { setError(t('collection.import.errors.socket_required')); return; }
      setFileAttente([]);
      envoyerMulti({ type: 'init', entrees });
      entrees.forEach((entree, id) => { envoyerPreuve(entree, id); });
      return;
    }
    setFileAttente(entrees.map((e, i) => ({ ...e, etat: i === 0 ? 'encours' : 'attente' })));
    await demarrerEntree(entrees[0]);
  };

  const demarrerEntree = async (entree) => {
    if (!entree) return;
    if (entree.mode === 'paquet') {
      addLog(t('collection.import.log.creating_zip_from_files'));
      const zip = await zipperFichiers(entree.fichiers);
      addLog(t('collection.import.log.zip_created_uploading', { size: (zip.size / 1024 / 1024).toFixed(1) }));
      await handleFile(zip);
    } else {
      await handleFile(entree.fichiers[0]);
    }
  };

  const handleFile = async (file) => {
    if (!file || !caseId) return;
    setFileName(file.name);
    setError('');
    setPipelineLog([]);
    setHayabusa(HAYABUSA_VIDE);
    setEchecEtape(null);
    setDebutParsing(null);
    setResults(null);

    if (!socket) { setError(t('collection.import.errors.socket_required')); return; }

    const probe = await probeFile(file);
    if (!probe.readable) {
      setError(probe.reason === 'empty'
        ? t('collection.import.errors.file_empty', { name: file.name })
        : t('collection.import.errors.file_unreadable', { name: file.name }));
      setStep('idle');
      return;
    }

    const formData = new FormData();
    formData.append('collection', file);
    formData.append('socketId', socket.id || '');

    try {
      setStep('uploading');
      addLog(t('collection.import.log.uploading_file', { name: file.name, size: (file.size / 1024 / 1024).toFixed(1) }));

      const importRes = await collectionAPI.import(caseId, formData, (e) => {
        setOctets({ recus: e.loaded || 0, total: e.total || 0 });
      });

      const dir = importRes.data?.collection_dir || '';
      setCollDir(dir);
      addLog(t('collection.import.log.upload_done'));
      setStep('extracting');

      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);
          reject(new Error(t('collection.import.errors.extraction_timeout')));
        }, 20 * 60 * 1000);

        function onDone_(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);

          setStep('detecting');
          addLog(t('collection.import.log.detecting_artifacts'));

          const detectedArtifacts = data?.detected_artifacts || null;
          if (data?.collection_dir) setCollDir(data.collection_dir);
          if (data?.hashes) setFileHashes(data.hashes);

          if (detectedArtifacts && Object.keys(detectedArtifacts).length > 0) {
            const normalized = {};
            for (const [k, v] of Object.entries(detectedArtifacts)) {
              normalized[k] = {
                n: v.count || v.n || 0,
                sz: v.size || v.sz || '?',
                ok: (v.count || v.n || 0) > 0,
                platform: v.platform || null,
              };
            }
            setDetected(normalized);
            if (data.arbre) { setArbre(data.arbre); setPile(vueDeDepart(data.arbre)); }
            setSelected(Object.keys(normalized).filter(k => normalized[k].ok));
            const isCatScale = 'catscale' in normalized;
            addLog(isCatScale
              ? t('collection.import.log.catscale_detected', { count: normalized.catscale.n })
              : t('collection.import.log.windows_detected', { count: Object.keys(normalized).length }));
          } else {
            addLog(t('collection.import.log.no_artifacts_detected'), 'ignore');
            setDetected({});
            setSelected([]);
          }

          setStep('detected');
          resolve();
        }

        function onError_(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);
          reject(new Error(data?.details || data?.error || t('collection.import.errors.extraction')));
        }

        socket.on('collection:import:done', onDone_);
        socket.on('collection:import:error', onError_);
      });
    } catch (err) {
      const rawErr = err.response?.data?.error;
      const msg = (typeof rawErr === 'string' ? rawErr : rawErr?.message) || err.response?.data?.message || err.message || t('collection.import.errors.import');
      setError(msg);
      addLog(t('collection.import.log.fatal_error', { error: msg }), 'erreur');
      setEchecEtape(stepRef.current);
      setStep('idle');
    }
  };

  const isCatScaleCollection = detected && 'catscale' in detected;

  const startParsing = async () => {
    if (!caseId || selected.length === 0) return;
    setParserStates(Object.fromEntries(selected.map(k => [k, { status: 'queued' }])));
    try {
      setStep('parsing');
      const parseTypes = isCatScaleCollection ? ['catscale'] : selected;
      const hasEvtx = !isCatScaleCollection && parseTypes.includes('evtx');

      addLog(isCatScaleCollection
        ? t('collection.import.log.start_catscale_parse')
        : t('collection.import.log.start_parse', { count: parseTypes.length }));

      try {
        await collectionAPI.parse(caseId, {
          collection_dir: collDir,
          artifact_types: isCatScaleCollection ? 'all' : parseTypes,
          socketId,
          ...(!isCatScaleCollection && parseTypes.includes('mft') ? { parser_options: { mft: optionsMft } } : {}),
        });
      } catch (e) {
        const errMsg = (e.response?.data?.error || e.message || t('common.unknown'))
          + (e.response?.data?.details ? ' — ' + e.response.data.details : '');
        addLog(t('collection.import.log.parse_api_error', { error: errMsg }), 'erreur');
        setError(errMsg);
        setEchecEtape('parsing');
        setStep('idle');
        return;
      }

      const doneData = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          reject(new Error(t('collection.import.errors.parsing_timeout')));
        }, 2 * 60 * 60 * 1000);

        function onParseDone(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          resolve(data);
        }
        function onParseError(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          reject(new Error(data?.details || data?.error || t('collection.import.errors.parsing')));
        }

        socket.on('collection:parse:done', onParseDone);
        socket.on('collection:parse:error', onParseError);
      });

      const perResults = doneData?.results || {};
      let totalOk = 0, totalSkip = 0, totalErr = 0;
      for (const r of Object.values(perResults)) {
        if (r.status === 'success') totalOk++;
        else if (r.status === 'skipped') totalSkip++;
        else if (r.status === 'error') totalErr++;
      }

      const total = doneData?.total_records || 0;
      addLog(t('collection.import.log.parsing_done', {
        count: total.toLocaleString(locale),
        ok: totalOk,
        skipped: totalSkip,
        errors: totalErr,
      }), 'ok');
      setResults({ total, types: parseTypes });
      if (isCatScaleCollection && perResults.catscale) {
        setCatscaleDetail({
          hostname: perResults.catscale.hostname || 'linux-host',
          os_info: perResults.catscale.os_info || '',
          artifacts: perResults.catscale.artifacts || [],
          events: perResults.catscale.events || total,
        });
      }

      if (hasEvtx) {
        setDebutParsing(doneData?.started_at || null);
        setStep('hayabusa');
        addLog(t('collection.import.log.hayabusa_server'));
        return;
      }

      setStep('done');
      addLog(t('collection.import.log.pipeline_done'));
      onDone?.();
    } catch (err) {
      setError(err.message || t('collection.import.errors.parsing'));
      addLog(t('collection.import.log.fatal_error', { error: err.message }), 'erreur');
      setEchecEtape(stepRef.current);
      setStep('idle');
    }
  };

  const reset = () => {
    envoyerMulti({ type: 'vider' });
    setStep('idle'); setDetected(null); setResults(null); setArbre(null); setPile([]);
    setHayabusa(HAYABUSA_VIDE); setEchecEtape(null); setDebutParsing(null); setPipelineLog([]); setFileName('');
    setFileHashes(null); setError(''); setCatscaleDetail(null); setCatscaleStep(null);
  };

  const toggle = (t) => setSelected(p => p.includes(t) ? p.filter(x => x !== t) : [...p, t]);
  const isProcessing = ['uploading', 'extracting', 'detecting', 'parsing', 'hayabusa'].includes(step);

  const willRunHayabusa = !isCatScaleCollection && selected.includes('evtx');
  const etapesChaine = etapesDeChaine({ avecHayabusa: willRunHayabusa });
  const idxHayabusa = etapesChaine.indexOf('hayabusa');
  const echecIdx = step === 'idle' && echecEtape ? indexDEtape(echecEtape, etapesChaine)
    : step === 'done' && hayabusa.statut === 'erreur' && idxHayabusa >= 0 ? idxHayabusa
    : null;
  const idxEtape = echecIdx !== null && step === 'idle' ? echecIdx : indexDEtape(step, etapesChaine);
  const maillons = etatsDeChaine({ etapes: etapesChaine, index: idxEtape, echec: echecIdx });
  const afficherChaine = isProcessing || step === 'done' || (step === 'idle' && echecIdx !== null && echecIdx >= 0);
  const etatsParseurs = Object.values(parserStates || {});
  const finisParseurs = etatsParseurs.filter(p => p && ['done', 'skipped', 'error'].includes(p.status)).length;
  const totalParseurs = etatsParseurs.length || selected.length;
  const lignesParseurs = etatsParseurs.reduce((n, p) => n + (Number(p && p.records) || 0), 0);
  const pasParseurs = avancement(parserStates);
  const tries = artefactsTries(detected);
  const totalFichiers = tries.reduce((n, a) => n + a.fichiers, 0);
  const maxFichiers = Math.max(1, ...tries.map(a => a.fichiers));
  const plateformesVues = new Set(Object.keys(detected || {}).map(k => ARTIFACTS[k]?.platform).filter(Boolean));
  const plateformeCollecte = plateformesVues.size === 1 ? [...plateformesVues][0] : null;
  const catalogueP = Object.fromEntries(Object.entries(ARTIFACTS).map(([k, a]) => [k, a.platform || null]));
  const absents = typesAbsents(detected, catalogueP, plateformeCollecte);
  const courant = pile.length ? pile[pile.length - 1] : null;
  const basculerTypes = (types, activer) => setSelected(p => {
    const s2 = new Set(p);
    for (const t of types) { if (activer) s2.add(t); else s2.delete(t); }
    return [...s2];
  });
  const etatDesEtapes = {
    upload: { octetsRecus: octets.recus, octetsTotal: octets.total },
    extract: { fichiers: idxEtape > 1 ? (totalFichiers || null) : null },
    detect: { types: tries.length },
    parse: { parseursFinis: finisParseurs, parseursTotal: totalParseurs, lignes: lignesParseurs, octetsLus: pasParseurs.octetsLus, octetsTotal: pasParseurs.octetsTotal },
    timeline: { lignes: lignesParseurs },
    hayabusa: { statut: hayabusa.statut, detections: hayabusa.detections },
  };
  const texteMesure = (cle, m) => {
    const n = (v) => Number(v || 0).toLocaleString(locale);
    if (m.indetermine) return t('collection.import.not_measurable');
    if (cle === 'upload') {
      return m.valeurs.total
        ? t('collection.import.measure_bytes', { recus: fmtOctets(m.valeurs.recus), total: fmtOctets(m.valeurs.total) })
        : t('collection.import.measure_received', { taille: fmtOctets(m.valeurs.recus) });
    }
    if (cle === 'extract') return t('collection.import.measure_files', { n: n(m.valeurs.fichiers) });
    if (cle === 'detect') return t('collection.import.measure_types', { n: n(m.valeurs.types) });
    if (cle === 'parse') {
      return m.mesure === 'octets'
        ? t('collection.import.measure_bytes_read', { lus: fmtOctets(m.valeurs.octetsLus), total: fmtOctets(m.valeurs.octetsTotal), lignes: n(m.valeurs.lignes) })
        : t('collection.import.measure_parsers', { finis: n(m.valeurs.finis), total: n(m.valeurs.total), lignes: n(m.valeurs.lignes) });
    }
    if (cle === 'timeline') return t('collection.import.measure_rows', { n: n(m.valeurs.lignes) });
    return '';
  };
  const texteMaillon = (cle, m, etat) => {
    const n = (v) => Number(v || 0).toLocaleString(locale);
    if (etat === 'attente') return t('collection.import.waiting');
    if (etat === 'erreur') return (cle === 'hayabusa' && hayabusa.erreur) || error || t('collection.import.chain.failed');
    if (cle === 'upload') {
      return etat === 'cours' && m.valeurs.total
        ? t('collection.import.measure_bytes', { recus: fmtOctets(m.valeurs.recus), total: fmtOctets(m.valeurs.total) })
        : fmtOctets(m.valeurs.total || m.valeurs.recus);
    }
    if (cle === 'extract') return m.indetermine ? t('collection.import.chain.in_progress') : t('collection.import.measure_files', { n: n(m.valeurs.fichiers) });
    if (cle === 'detect') return etat === 'cours' ? t('collection.import.chain.in_progress') : t('collection.import.chain.types', { n: n(m.valeurs.types) });
    if (cle === 'parse') {
      if (m.mesure === 'octets') {
        return etat === 'cours'
          ? t('collection.import.chain.bytes_read', { lus: fmtOctets(m.valeurs.octetsLus), total: fmtOctets(m.valeurs.octetsTotal) })
          : t('collection.import.chain.read_total', { total: fmtOctets(m.valeurs.octetsTotal) });
      }
      return t('collection.import.chain.parsers', { finis: n(m.valeurs.finis), total: n(m.valeurs.total) });
    }
    if (cle === 'timeline') return t('collection.import.chain.rows', { n: n(m.valeurs.lignes) });
    if (cle === 'hayabusa') {
      if (etat === 'fait') return t('collection.import.chain.detections', { n: n(m.valeurs.detections) });
      return hayabusa.statut === 'cours'
        ? t('collection.import.chain.evtx', { n: n(detected?.evtx?.n) })
        : t('collection.import.chain.hayabusa_wait');
    }
    return '';
  };
  const principal = step === 'parsing' ? parseurPrincipal(parserStates) : null;
  const rendreArbre = ({ pile: pileA, retenus, basculer, descendre, remonter }) => {
    const courantA = pileA.length ? pileA[pileA.length - 1] : null;
    if (!courantA) return null;
    const cheminA = pileA.map(x => x.nom).filter(Boolean).join('/') + '/';
    const rangeesA = enfantsAffiches(courantA);
    const maxA = Math.max(1, ...rangeesA.map(x => x.n));
    return (
      <>
        <div className="fl-det-fil">
          <button style={controlStyle(false)} {...controlHover(false)}
            disabled={pileA.length < 2}
            onClick={remonter}
            title={t('collection.import.go_up')}>←</button>
          <span className="fl-det-chemin" title={cheminA}>{cheminA}</span>
          <span className="fl-det-nb">
            {t('collection.import.file_count', { count: courantA.n, formate: courantA.n.toLocaleString(locale) })}
          </span>
        </div>
        {rangeesA.map((noeud) => {
          const ts = typesSous(noeud);
          const etat = etatCase(noeud, retenus);
          const descend = (noeud.enfants || []).length > 0;
          return (
            <div key={noeud.nom} className="fl-det-l">
              <input type="checkbox" checked={etat === 'plein'}
                ref={el => { if (el) el.indeterminate = etat === 'partiel'; }}
                onChange={() => basculer(ts, etat !== 'plein')} />
              <button className={descend ? 'fl-det-fleche' : 'fl-det-fleche fl-det-inerte'}
                disabled={!descend}
                onClick={() => descendre(noeud)}
                title={descend ? t('collection.import.go_down') : undefined}>
                {descend ? '\u25b8' : '\u00b7'}
              </button>
              <span className="fl-det-nom" title={noeud.nom}>{noeud.nom}{descend ? '/' : ''}</span>
              <span className="fl-det-sup" title={ts.map(artifactLabel).join(' · ')}>{ts.map(artifactLabel).join(' · ')}</span>
              <span className="fl-det-nb">
                {t('collection.import.file_count', { count: noeud.n, formate: noeud.n.toLocaleString(locale) })}
              </span>
              <span className="fl-det-jg"><i style={{ width: `${Math.max(1.2, (noeud.n / maxA) * 100)}%` }} /></span>
            </div>
          );
        })}
      </>
    );
  };
  const texteLigne = (e, l) => {
    const n = (v) => Number(v || 0).toLocaleString(locale);
    const etape = l.cle ? t(`collection.import.steps.${l.cle}`) : '';
    if (e.etat === 'attente') return t('collection.import.waiting');
    if (e.etat === 'revue') return `${etape} · ${t('collection.import.chain.awaiting_choice')}`;
    if (e.etat === 'detecte' && !e.lance && !e.catscale) return `${etape} · ${t('collection.import.chain.launch_in', { n: resteAvantLancement(e, maintenant) })}`;
    if (e.etat === 'erreur') return `${etape} · ${e.erreur || t('collection.import.chain.failed')}`;
    if (e.etat === 'fini') {
      if (e.hayabusa.statut === 'erreur') return `${t('collection.import.steps.hayabusa')} · ${e.hayabusa.erreur || t('collection.import.chain.failed')}`;
      return e.hayabusa.statut === 'fait'
        ? `${t('collection.import.chain.done')} · ${t('collection.import.chain.detections', { n: n(e.hayabusa.detections) })}`
        : t('collection.import.chain.done');
    }
    if (l.cle === 'upload') return `${etape} · ${t('collection.import.measure_bytes', { recus: fmtOctets(e.octets.recus), total: fmtOctets(e.octets.total) })}`;
    if (l.cle === 'parse') {
      const pas = avancement(e.parserStates);
      if (!pas.total) return `${etape} · ${t('collection.import.chain.queued')}`;
      return pas.mesure === 'octets'
        ? `${etape} · ${t('collection.import.chain.bytes_read', { lus: fmtOctets(pas.octetsLus), total: fmtOctets(pas.octetsTotal) })}`
        : `${etape} · ${t('collection.import.chain.parsers', { finis: n(pas.termines), total: n(pas.total) })}`;
    }
    if (l.cle === 'hayabusa') {
      return `${etape} · ${e.hayabusa.statut === 'cours' ? t('collection.import.chain.evtx', { n: n(e.detected?.evtx?.count ?? e.detected?.evtx?.n) }) : t('collection.import.chain.hayabusa_wait')}`;
    }
    return `${etape} · ${t('collection.import.chain.in_progress')}`;
  };
  const libelleEtape = step === 'uploading' ? t('collection.import.status.uploading')
    : step === 'extracting' ? t('collection.import.status.extracting')
    : step === 'detecting' ? t('collection.import.status.detecting')
    : step === 'hayabusa' ? t('collection.import.status.hayabusa')
    : step === 'parsing' && isCatScaleCollection && catscaleStep
      ? `${t('collection.import.status.parsing_linux')} ${catscaleStepLabel(catscaleStep)}`
      : step === 'parsing' ? t('collection.import.status.parsing') : '';
  const heureReleve = new Date(releve).toLocaleTimeString(locale);


  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

      {step === 'idle' && !multiEnCours && (
        <div
          className="rounded-xl cursor-pointer transition-all"
          style={{
            border: `2px dashed ${dragging ? 'var(--fl-accent)' : 'var(--fl-border2)'}`,
            background: dragging ? 'color-mix(in srgb, var(--fl-accent) 6%, transparent)' : 'var(--fl-bg)',
            padding: '48px 24px',
          }}
          onClick={() => fileRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={async e => {
            e.preventDefault();
            setDragging(false);
            const items = [...(e.dataTransfer.items || [])];
            const files = [...(e.dataTransfer.files || [])];

            const hasDirectory = items.some(it => it.webkitGetAsEntry?.()?.isDirectory);

            if (hasDirectory) {
              setStep('uploading');
              addLog(t('collection.import.log.creating_zip_from_files'));
              const zipFile = await buildZipFromItems(items);
              if (!zipFile) { setError(t('collection.import.errors.no_file_to_archive')); setStep('idle'); return; }
              addLog(t('collection.import.log.zip_created_uploading', { size: (zipFile.size / 1024 / 1024).toFixed(1) }));
              setStep('idle');
              setFileAttente([{ nom: zipFile.name, taille: zipFile.size, mode: 'paquet', fichiers: [zipFile], etat: 'encours' }]);
              handleFile(zipFile);
            } else {
              await accueillirDepot(files);
            }
          }}
        >
          <div className="text-center">
            <div style={{ width: 64, height: 64, borderRadius: '50%', margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: dragging ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'var(--fl-card)',
              border: `1px solid ${dragging ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`, transition: 'all 0.2s' }}>
              <Package size={28} style={{ color: dragging ? 'var(--fl-accent)' : 'var(--fl-muted)', transition: 'color 0.2s' }} />
            </div>
            <p className="text-base font-semibold mb-1" style={{ color: 'var(--fl-text)' }}>
              {t('collection.import.drop_title')}
            </p>
            <p className="text-sm mb-3" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.drop_subtitle')}</p>
            {caseObj && (
              <p className="text-xs mb-3" style={{ color: 'var(--fl-dim)' }}>
                {t('collection.import.target_case')} <strong style={{ color: 'var(--fl-accent)' }}>{caseObj.case_number}</strong>
              </p>
            )}
            <div style={{ ...MARK_ROW, justifyContent: 'center', marginBottom: 10 }}>
              <span style={markStyle('var(--fl-muted)')}>
                Windows — KAPE · Velociraptor · Magnet · CyLR
              </span>
              <span style={markStyle('var(--fl-muted)')}>
                Linux — CatScale
              </span>
            </div>
            <p className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>{t('collection.import.accepted_formats')}</p>
          </div>
          <input ref={fileRef} type="file" accept=".zip,.tar,.gz,.7z,.evtx,.pf,.lnk,.dat,.hve,.db,.sqlite,.pcap,.pcapng,.cap" multiple className="hidden"
            onChange={async e => {
              const files = [...e.target.files];
              if (files.length === 0) return;
              await accueillirDepot(files);
            }}
          />
        </div>
      )}

      {fileAttente.length > 0 && (
        <div className="fl-fq">
          {fileAttente.map((e, i) => (
            <div key={`${e.nom}-${i}`} className={`fl-fi fl-fi-${e.etat}`}>
              <span className="fl-fi-r">{i + 1}</span>
              <span className="fl-fi-n" title={e.nom}>{e.nom}</span>
              <span className="fl-fi-t">{fmtOctets(e.taille)}</span>
              <span className="fl-fi-e">
                {e.etat === 'encours' ? (libelleEtape || t('collection.import.queue_running'))
                  : e.etat === 'fini' ? t('collection.import.queue_done')
                  : t('collection.import.queue_waiting')}
              </span>
              {e.etat === 'attente' && (
                <button className="fl-fi-x" title={t('collection.import.remove_from_queue')}
                  onClick={() => setFileAttente(f => f.filter((_, j) => j !== i))}>×</button>
              )}
            </div>
          ))}
        </div>
      )}

      {Array.isArray(multi) && (
        <div className="fl-mp">
          {multi.map(e => {
            const l = ligneDeChaine(e);
            return (
              <div key={e.id} className="fl-mp-l">
                <span className="fl-mp-n" title={e.nom}>{e.nom}</span>
                <span className="fl-mp-pf">{e.catscale ? t('collection.import.platform_linux') : e.types.length ? t('collection.import.platform_windows') : ''}</span>
                <span className={l.reussi ? 'fl-mp-mini fl-mp-reussi' : 'fl-mp-mini'}>
                  {l.maillons.map(m => (
                    <i key={m.cle} className={`fl-mp-${m.etat}`}>
                      {m.etat === 'cours' && l.pct !== null ? <b style={{ width: `${l.pct}%` }} /> : null}
                    </i>
                  ))}
                </span>
                <span className="fl-mp-c">
                  <span>{texteLigne(e, l)}</span>
                  {e.etat === 'detecte' && !e.lance && !e.catscale && (
                    <button style={controlStyle(false)} {...controlHover(false)} onClick={() => envoyerMulti({ type: 'revoir', id: e.id })}>
                      {t('collection.import.review')}
                    </button>
                  )}
                </span>
                {e.etat === 'revue' && (
                  <div className="fl-mp-rev">
                    <div className="fl-mp-rev-tete">
                      <span className="fl-mp-rev-t">{t('collection.import.review_count', { n: e.retenus.length, total: e.types.length })}</span>
                      <span className="fl-mp-rev-d">
                        <button style={controlStyle(false)} {...controlHover(false)} onClick={() => envoyerMulti({ type: 'tout', id: e.id })}>
                          {e.retenus.length === e.types.length ? t('collection.import.deselect_all') : t('collection.import.select_all')}
                        </button>
                        <button style={controlStyle(true)} {...controlHover(true)} disabled={!e.retenus.length} onClick={() => envoyerMulti({ type: 'lancer', id: e.id })}>
                          {t('collection.import.launch_parsing')}
                        </button>
                      </span>
                    </div>
                    {rendreArbre({
                      pile: e.pile,
                      retenus: new Set(e.retenus),
                      basculer: (types, activer) => envoyerMulti({ type: 'selection', id: e.id, types, activer }),
                      descendre: (noeud) => envoyerMulti({ type: 'descendre', id: e.id, noeud }),
                      remonter: () => envoyerMulti({ type: 'remonter', id: e.id }),
                    })}
                  </div>
                )}
              </div>
            );
          })}
          {multiTermine && (
            <button onClick={reset} className="fl-btn fl-btn-secondary">{t('collection.import.new_collection')}</button>
          )}
        </div>
      )}

      {afficherChaine && (
        <div className="fl-imp">
          <div className="fl-imp-tete">
            <span className="fl-imp-etat">{libelleEtape}</span>
            <span className="fl-imp-relev">{t('collection.import.last_event', { heure: heureReleve })}</span>
          </div>
          <div className={step === 'done' && echecIdx === null ? 'fl-ch fl-ch-reussi' : 'fl-ch'}>
            {maillons.map(({ cle, etat }) => {
              const m = mesureDEtape(cle, etatDesEtapes[cle]);
              const mesurable = etat === 'cours' && m.pct !== null && !m.indetermine;
              return (
                <div key={cle} className={`fl-ch-e fl-ch-${etat}${etat === 'cours' && !mesurable ? ' fl-ch-indet' : ''}`}>
                  <span className="fl-ch-barre"><i style={mesurable ? { width: `${m.pct}%` } : undefined} /></span>
                  <span className="fl-ch-nom">{t(`collection.import.steps.${cle}`)}</span>
                  <span className="fl-ch-val">{texteMaillon(cle, m, etat)}</span>
                </div>
              );
            })}
          </div>
          {step === 'hayabusa' && <div className="fl-ch-pied">{t('collection.import.chain.continue')}</div>}
          {principal && (
            <div className="fl-ch-pied">
              {t('collection.pm_running')} <b>{ARTIFACTS[principal.cle] ? artifactLabel(principal.cle) : principal.cle}</b>{' '}
              {t('collection.pm_running_share', { taille: fmtOctets(principal.octets), part: principal.part })}
            </div>
          )}
          {Object.keys(parserStates).length > 0 && (
            <ParseursDepliant
              parseurs={Object.keys(parserStates).map(k => ({ key: k, name: ARTIFACTS[k] ? artifactLabel(k) : k }))}
              etats={parserStates}
              fichiers={detected ? Object.fromEntries(Object.entries(detected).map(([k, v]) => [k, v.n])) : {}}
              onChoisir={cle => setRequeteJournal(r => (r === cle ? '' : cle))}
            />
          )}
        </div>
      )}

      {fileHashes && (fileHashes.md5 || fileHashes.sha256) && (
        <div className="fl-card p-4">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <p className="text-xs font-mono" style={{ color: 'var(--fl-dim)', margin: 0 }}>
              {t('collection.import.integrity_title', { fileName })}
            </p>
            <span style={{ flex: 1 }} />
            <span className="fl-imp-relev">
              {t('collection.import.hashes_computed', {
                date: new Date(empreinteA).toLocaleString(locale, { hour12: false }),
              })}
            </span>
          </div>
          <div className="space-y-1.5">
            {[['MD5', fileHashes.md5, 'var(--fl-muted)'], ['SHA-1', fileHashes.sha1, 'var(--fl-gold)'], ['SHA-256', fileHashes.sha256, 'var(--fl-accent)']].map(([label, value, color]) => value && (
              <div key={label} className="fl-emp-l">
                <span className="flex-shrink-0" style={{ ...markStyle(color, FS_MARK_SM), minWidth: 56 }}>{label}</span>
                <span className="font-mono text-xs flex-1 break-all" style={{ color: 'var(--fl-dim)' }}>{value}</span>
                <button onClick={() => { navigator.clipboard.writeText(value); setCopiedHash(label); setTimeout(() => setCopiedHash(c => c === label ? null : c), 1400); }}
                  className="flex-shrink-0 inline-flex items-center gap-1 text-xs px-2 py-1 rounded font-mono"
                  style={{ background: 'transparent', color: copiedHash === label ? 'var(--fl-ok)' : 'var(--fl-muted)', border: `1px solid ${copiedHash === label ? 'color-mix(in srgb, var(--fl-ok) 35%, transparent)' : 'var(--fl-border)'}`, transition: 'all 0.15s' }}>
                  {copiedHash === label ? <><CheckCircle2 size={11} /> {t('collection.import.copied')}</> : <><Copy size={11} /> {t('common.copy').toLowerCase()}</>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length === 0 && (
        <div className="fl-card p-5 text-center">
          <AlertTriangle size={28} style={{ color: 'var(--fl-gold)', margin: '0 auto 8px' }} />
          <p className="text-sm font-mono" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.no_artifact_title')}</p>
          <p className="text-xs mt-1" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.no_artifact_hint')}</p>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length > 0 && (
        <div className="fl-card p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <p className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.detected_artifacts')}</p>
              {isCatScaleCollection ? (
                <span className="fl-det-resume">Linux / CatScale</span>
              ) : (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>Windows</span>
              )}
            </div>
            {!isCatScaleCollection && (
              <button onClick={() => setSelected(Object.keys(detected).filter(k => detected[k].ok !== false))} className="fl-btn fl-btn-ghost fl-btn-sm">
                {t('collection.import.select_all')}
              </button>
            )}
          </div>

          {isCatScaleCollection ? (
            <div style={{ background: 'var(--fl-bg)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)', borderRadius: 8, padding: '14px 16px', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <Terminal size={14} style={{ color: 'var(--fl-ok)' }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-ok)' }}>{t('collection.import.catscale_archive')}</span>
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', marginLeft: 'auto', fontFeatureSettings: '"tnum"' }}>
                  {t('collection.import.file_count', { count: (detected.catscale?.n || 0).toLocaleString(locale) })}{detected.catscale?.sz && detected.catscale.sz !== '?' ? ` · ${detected.catscale.sz}` : ''}
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                {Object.entries(CATSCALE_STEPS).map(([key, { icon: Icon }]) => (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 10px', borderRadius: 5, background: 'var(--fl-panel)', border: '1px solid var(--fl-panel)' }}>
                    <Icon size={11} style={{ color: 'var(--fl-ok)', flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>{catscaleStepLabel(key)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="fl-det">
              <div className="fl-det-resume">
                {t('collection.import.detection_summary', { types: tries.length, fichiers: (courant ? courant.n : totalFichiers).toLocaleString(locale) })}
                {absents.length > 0 && ` · ${t('collection.import.absent_count', { n: absents.length, plateforme: plateformeCollecte })}`}
              </div>

              {rendreArbre({
                pile,
                retenus: new Set(selected),
                basculer: basculerTypes,
                descendre: (noeud) => setPile(p => [...p, noeud]),
                remonter: () => setPile(p => p.slice(0, -1)),
              })}

              {absents.length > 0 && (
                <div className="fl-det-absents">
                  {t('collection.import.absent_types', { liste: absents.join('  ') })}
                </div>
              )}
            </div>
          )}

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              {isCatScaleCollection ? (
                <span className="text-sm" style={{ color: 'var(--fl-ok)' }}>{t('collection.import.linux_parsers')}</span>
              ) : (
                <>
                  <span className="text-sm" style={{ color: 'var(--fl-dim)' }}><strong style={{ color: 'var(--fl-text)' }}>{selected.length}</strong> {t('collection.import.selected_count_suffix')}</span>
                  {selected.includes('evtx') && (
                    <span className="fl-det-resume">{t('collection.import.hayabusa_included')}</span>
                  )}
                  {selected.includes('mft') && (
                    <fieldset style={{ display: 'flex', gap: 12, border: 'none', margin: 0, padding: 0 }}>
                      <legend className="fl-det-resume" style={{ float: 'left', marginRight: 8 }}>{t('collection.import.mft_options')}</legend>
                      {['recover_slack', 'include_resident_data'].map(cle => (
                        <label key={cle} className="fl-det-resume" title={t(`collection.import.mft_${cle}_hint`)}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                          <input type="checkbox" checked={optionsMft[cle]}
                            onChange={e => setOptionsMft(o => ({ ...o, [cle]: e.target.checked }))} />
                          {t(`collection.import.mft_${cle}`)}
                        </label>
                      ))}
                    </fieldset>
                  )}
                </>
              )}
            </div>
            <button onClick={startParsing} disabled={!selected.length && !isCatScaleCollection}
              style={{ ...controlStyle(true), opacity: (selected.length || isCatScaleCollection) ? 1 : 0.4 }}>
              {isCatScaleCollection ? t('collection.import.analyze_linux') : t('collection.import.start_pipeline')} →
            </button>
          </div>
        </div>
      )}

      {step === 'done' && (
        <div className="fl-card p-5">
          <div className="flex items-center gap-3 mb-4">
            <div style={{ width: 34, height: 34, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              background: 'color-mix(in srgb, var(--fl-ok) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 30%, transparent)' }}>
              <CheckCircle2 size={18} style={{ color: 'var(--fl-ok)' }} />
            </div>
            <div>
              <div className="text-base font-semibold" style={{ color: 'var(--fl-text)' }}>{t('collection.import.analysis_done')}</div>
              {results && <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', marginTop: 2 }}>
                <span style={{ color: 'var(--fl-ok)', fontWeight: 700 }}>{(results.total || 0).toLocaleString(locale)}</span> {t('collection.import.events_label')} · {t('collection.import.artifact_type_count', { count: results.types?.length || 0 })}
              </div>}
            </div>
            {catscaleDetail && (
              <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)' }}>
                <Server size={11} />
                {catscaleDetail.hostname}
                {catscaleDetail.os_info && <span style={{ color: 'var(--fl-dim)' }}>— {catscaleDetail.os_info}</span>}
              </span>
            )}
          </div>

          {catscaleDetail ? (
            <div className="mb-4">
              <p className="text-xs font-mono mb-3" style={{ color: 'var(--fl-dim)' }}>
                {t('collection.import.events_imported', { count: catscaleDetail.events.toLocaleString(locale) })}
              </p>
              {catscaleDetail.artifacts.length > 0 && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 4 }}>
                  {catscaleDetail.artifacts.map((raw, i) => {
                    const { type, label, count } = parseCatScaleArtifact(raw);
                    const color = CATSCALE_TYPE_COLORS[type] || 'var(--fl-muted)';
                    return (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px', borderRadius: 5, background: 'var(--fl-bg)', border: `1px solid color-mix(in srgb, ${color} 13%, transparent)` }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                        <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color, flexShrink: 0 }}>{count.toLocaleString(locale)}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : results && (
            <div className="mb-4">
              <div className="flex flex-wrap gap-2 mb-2">
                {results.types.map(t => {
                  const art = ARTIFACTS[t];
                  return (
                    <span key={t} className="fl-badge" style={{ background: `color-mix(in srgb, ${art?.color} 8%, transparent)`, color: art?.color, border: `1px solid color-mix(in srgb, ${art?.color} 16%, transparent)` }}>
                      {art?.parser || t}
                    </span>
                  );
                })}
              </div>
              <p className="text-sm mb-2" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.records_imported', { count: results.total.toLocaleString(locale) })}</p>
              <StatusRollup parserStates={parserStates} t={t} />
            </div>
          )}

          <button onClick={reset} className="fl-btn fl-btn-secondary">{t('collection.import.new_collection')}</button>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg text-sm flex items-center gap-2" style={{ background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: 'var(--fl-danger)' }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError('')} className="ml-auto"><X size={14} /></button>
        </div>
      )}

      <ParseTerminal
        caseId={caseId}
        socket={socketAffaire}
        preuves={Array.isArray(multi) ? multi.map(e => e.collDir).filter(Boolean) : (collDir ? [collDir] : [])}
        lignesNavigateur={pipelineLog}
        provenance={Array.isArray(multi)
          ? multi.map(e => ({ nom: e.nom, sha256: null }))
          : (fileName ? [{ nom: fileName, sha256: fileHashes?.sha256 || null }] : [])}
        titre={t('collection.import.journal.titre', {
          preuve: Array.isArray(multi) ? multi.map(e => e.nom).join(', ') : (fileName || t('collection.import.journal.titre_affaire')),
        })}
        requete={requeteJournal}
        onRequete={setRequeteJournal}
      />
    </div>
  );
}
