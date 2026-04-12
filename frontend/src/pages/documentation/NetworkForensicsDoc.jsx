import { useState, useMemo } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react';
import { useTheme } from '../../utils/theme';

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1800); }); }}
      title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 6px', borderRadius: 4, cursor: 'pointer',
        fontSize: 9, fontFamily: 'monospace', flexShrink: 0,
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
      }}>
      {ok ? <CheckCheck size={9} /> : <Copy size={9} />}
    </button>
  );
}

const TOPICS = [
  {
    id: 'pcap-analysis',
    title: 'Analyse PCAP — Méthodologie',
    icon: '📦',
    category: 'PCAP',
    summary: "Approche structurée pour l'analyse de captures réseau. Partir des statistiques globales pour identifier les flux suspects, puis descendre au niveau paquet.",
    content: [
      {
        label: 'Tshark — Statistiques globales',
        items: [
          'tshark -r capture.pcap -q -z io,stat,60  # trafic par minute',
          'tshark -r capture.pcap -q -z conv,tcp  # top conversations TCP',
          'tshark -r capture.pcap -q -z endpoints,ip  # top IPs',
          'tshark -r capture.pcap -q -z http,tree  # stats HTTP',
        ],
      },
      {
        label: 'Wireshark — Filtres d\'investigation',
        items: [
          'http.request.method == "POST"  # uploads',
          'dns.qry.name contains "evil"  # domaines suspects',
          'tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN scan',
          'ssl.handshake.type == 1 && !ssl.handshake.extensions_server_name  # TLS sans SNI',
          'smb2.cmd == 0x0005 && smb2.nt_status != 0  # erreurs SMB auth',
          'kerberos.msg_type == 10 && kerberos.error_code == 18  # Kerberos pre-auth fail',
        ],
      },
      {
        label: 'Zeek (Bro) — Logs structurés',
        items: [
          'zeek -r capture.pcap  # génère conn.log, dns.log, http.log, ssl.log, files.log',
          'cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration bytes  # connexions',
          'cat http.log | zeek-cut ts host uri method resp_mime_types  # HTTP',
          'cat ssl.log | zeek-cut ts id.orig_h id.resp_h server_name ja3 ja3s  # TLS/JA3',
          'cat dns.log | zeek-cut ts query qtype_name answers  # DNS',
          'cat files.log | zeek-cut ts filename mime_type md5  # fichiers transférés',
        ],
      },
    ],
    iocs: [
      'Connexion TCP vers port 4444, 1234, 8888 (Meterpreter defaults)',
      'TLS sans SNI vers IP publique (C2)',
      'Volume élevé de SYN sans ACK (scan)',
      'DNS vers domaines DGA (entropie élevée)',
      'SMB auth failures en masse (PtH bruteforce)',
    ],
  },
  {
    id: 'beaconing-detection',
    title: 'Détection de Beaconing C2',
    icon: '📡',
    category: 'C2 Detection',
    summary: "Les implants C2 (Cobalt Strike, Sliver, Meterpreter) communiquent à intervalles réguliers avec leur serveur. Détecter ces patterns de beaconing est clé pour identifier les compromissions actives.",
    content: [
      {
        label: 'Indicateurs de beaconing',
        items: [
          'Connexions HTTP(S) régulières vers même destination (même heure ± jitter)',
          'User-Agent statique, identique sur tous les beacons (contrairement aux vrais navigateurs)',
          'Réponses HTTP minimales (200 OK avec body vide ou quelques bytes)',
          'Certificat TLS auto-signé ou avec attributs par défaut',
          'Pas de Referer, Cookie, ou Accept-Language dans les requêtes',
        ],
      },
      {
        label: 'Détection avec Zeek + rita',
        items: [
          '# RITA (Real Intelligence Threat Analytics)',
          'rita import /path/to/zeek/logs/ database_name',
          'rita show-beacons database_name | head 20',
          '# Score de beaconing basé sur régularité temporelle',
          '# > 0.8 = beaconing très probable',
        ],
      },
      {
        label: 'Analyse manuelle des intervalles (Python)',
        items: [
          '# Extraire timestamps connexions vers IP suspecte',
          "tshark -r cap.pcap -Y 'ip.dst==1.2.3.4 && tcp.flags.syn==1' -T fields -e frame.time_epoch > times.txt",
          '# Calculer intervalles entre connexions',
          'python3 -c "import sys; t=[float(l) for l in open(\'times.txt\')]; print([t[i+1]-t[i] for i in range(len(t)-1)])"',
        ],
      },
      {
        label: 'JA3/JA3S — TLS Fingerprinting',
        items: [
          '# JA3 = fingerprint du client TLS (identifie Cobalt Strike, Sliver...)',
          '# JA3S = fingerprint du serveur TLS (identifie C2 framework)',
          'cat ssl.log | zeek-cut ja3 | sort | uniq -c | sort -rn',
          '# Base de données JA3 connus : https://ja3er.com',
          '# Cobalt Strike default JA3 : 72a7c4c38c0eb4ad3716c54aa3a955cc',
        ],
      },
    ],
    iocs: [
      'Intervalles connexions identiques à ± 5% (sleep + jitter Cobalt Strike)',
      'JA3 hash correspondant à Cobalt Strike, Metasploit, Sliver',
      'HTTP GET régulier avec body vide en réponse',
      'User-Agent identique sur toutes les connexions (Mozilla/5.0 statique)',
      'POST avec contenu binaire encodé Base64 ou AES vers même IP',
    ],
  },
  {
    id: 'dns-analysis',
    title: 'Analyse DNS — Détection d\'Anomalies',
    icon: '🔍',
    category: 'DNS',
    summary: "Les logs DNS révèlent les domaines C2, les malwares DGA, les tunnels DNS et les tentatives de phishing. Source souvent sous-exploitée en forensique réseau.",
    content: [
      {
        label: 'Détection DGA (Domain Generation Algorithm)',
        items: [
          '# Caractéristiques DGA : entropie élevée, longueur > 15 chars, peu de voyelles',
          "cat dns.log | zeek-cut query | awk 'length($0)>15' | sort | uniq -c | sort -rn",
          '# Script Python — calcul entropie',
          'python3 -c "import math; s=\'xn5k2abc3def4\'; e=-sum(s.count(c)/len(s)*math.log2(s.count(c)/len(s)) for c in set(s)); print(round(e,2))"',
          '# Entropie > 3.5 = suspect pour nom de domaine',
          '# Utiliser DGAdetect ou dnstwist pour validation',
        ],
      },
      {
        label: 'Domaines suspects — Analyse rapide',
        items: [
          '# Top domaines résolus',
          'cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head 30',
          '# Domaines avec peu de résolutions (C2 unique)',
          'cat dns.log | zeek-cut query | sort | uniq -c | sort -n | head 20',
          '# Requêtes NXDomain (domaines inexistants)',
          'cat dns.log | zeek-cut query rcode_name | grep NXDOMAIN | awk \'{print $1}\' | sort | uniq -c | sort -rn',
          '# Requêtes TXT (DNS tunneling)',
          'cat dns.log | zeek-cut query qtype_name | grep TXT',
          '# Sous-domaines longs (DNS tunneling)',
          "cat dns.log | zeek-cut query | awk -F. '{if(length($1)>30) print}' | head 20",
        ],
      },
      {
        label: 'Passive DNS — Corrélation temporelle',
        items: [
          '# Premier enregistrement du domaine (via Virustotal, Shodan)',
          '# Domaine créé < 24h avant l\'incident = infrastructure attaquant',
          '# Résolutions rapides puis abandon (fast-flux C2)',
          '# TTL très bas (< 60 secondes) = infrastructure temporaire',
          'tshark -r cap.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name -e frame.time | sort',
        ],
      },
    ],
    iocs: [
      'Domaine avec entropie > 3.5 (DGA)',
      'Sous-domaines > 30 caractères (DNS tunneling)',
      'Volume > 100 requêtes TXT par minute',
      'Même machine résolvant des dizaines de FQDNs uniques en < 60s (SharpHound)',
      'Requêtes DNS vers .onion, .bit, ou TLDs rares',
      'TTL < 30 secondes (fast-flux C2)',
    ],
  },
  {
    id: 'lateral-movement-network',
    title: 'Mouvement Latéral — Signatures Réseau',
    icon: '↔️',
    category: 'Lateral Movement',
    summary: "Identifier le mouvement latéral depuis les logs réseau en analysant les patterns d'authentification SMB, RDP, Kerberos et les connexions inhabituelles entre endpoints.",
    content: [
      {
        label: 'SMB — Analyse',
        items: [
          '# Connexions SMB entre workstations (anormal)',
          "tshark -r cap.pcap -Y 'smb2' -T fields -e ip.src -e ip.dst -e smb2.cmd | sort | uniq -c | sort -rn",
          '# Admin shares access (ADMIN$, C$, IPC$)',
          "tshark -r cap.pcap -Y 'smb2.filename contains \"ADMIN$\"'",
          '# Pass-the-Hash : NTLM auth sans session Kerberos préalable',
          "cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | awk '$3==445' | sort | uniq -c | sort -rn",
        ],
      },
      {
        label: 'RDP — Analyse',
        items: [
          '# Connexions RDP (port 3389)',
          "cat conn.log | zeek-cut id.orig_h id.resp_h | awk '{print \"RDP: \"$1\" -> \"$2}' | sort | uniq",
          '# Tshark : handshake RDP',
          "tshark -r cap.pcap -Y 'tcp.port==3389 && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e ip.dst",
          '# Durée des sessions RDP (courte = recon, longue = hands-on)',
          "cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk '$3>0 {print}' | sort -k3 -rn | head",
        ],
      },
      {
        label: 'Kerberos — Anomalies',
        items: [
          '# AS-REP sans pré-authentification (AS-REP Roasting)',
          "tshark -r cap.pcap -Y 'kerberos.msg_type == 11'  # AS-REP",
          '# TGS-REQ volume élevé (Kerberoasting)',
          "tshark -r cap.pcap -Y 'kerberos.msg_type == 12' -T fields -e ip.src | sort | uniq -c | sort -rn",
          '# RC4 encryption (ETYPE 17/23 = Kerberoast cible)',
          "tshark -r cap.pcap -Y 'kerberos.etype == 23'",
          '# Golden ticket : TGT avec durée anormale',
          "cat kerberos.log | zeek-cut client id.orig_h request_type | awk '$3==\"TGT\"'",
        ],
      },
      {
        label: 'WMI / DCOM Réseau',
        items: [
          '# DCOM (port 135 + ports dynamiques)',
          "tshark -r cap.pcap -Y 'tcp.port==135' -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn",
          '# WMI remote : connexion 135 suivi connexion > 49152',
          "cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | awk '$3>49152 || $3==135' | sort",
        ],
      },
    ],
    iocs: [
      'Connexions SMB entre workstations (devrait être workstation → serveur uniquement)',
      'RDP depuis une machine non-admin vers serveur critique',
      'NTLM auth sans Kerberos préalable (PtH indicator)',
      'Kerberos TGS-REQ en volume depuis même source (Kerberoasting)',
      'RC4 enctype pour des comptes configurés AES',
    ],
  },
  {
    id: 'exfiltration-network',
    title: 'Détection d\'Exfiltration Réseau',
    icon: '📤',
    category: 'Exfiltration',
    summary: "Identifier l'exfiltration de données depuis les métriques de trafic réseau : volume, destinations, protocoles et anomalies comportementales.",
    content: [
      {
        label: 'Volume et bytes — Anomalies',
        items: [
          '# Top sources par bytes envoyés (uploaded)',
          'cat conn.log | zeek-cut id.orig_h orig_bytes | awk \'{sum[$1]+=$2} END{for(ip in sum) print sum[ip], ip}\' | sort -rn | head 20',
          '# Connexions avec fort ratio upload/download',
          'cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes | awk \'{if($3>$4*10 && $3>1000000) print}\' | sort -k3 -rn',
          '# Trafic HTTPS sortant hors heures de travail',
          "cat conn.log | zeek-cut ts id.orig_h orig_bytes | awk '{h=strftime(\"%H\",int($1)); if(h<7||h>20) print}'",
        ],
      },
      {
        label: 'Destinations — Réputation',
        items: [
          '# IPs externes contactées (hors RFC1918)',
          "cat conn.log | zeek-cut id.resp_h | grep -vE '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)' | sort | uniq -c | sort -rn",
          '# Nouvelles IPs jamais vues avant J-7',
          '# (nécessite baseline conn.log)',
          '# Résolution inverse des IPs suspectes',
          'for ip in $(cat suspicious_ips.txt); do host $ip; done',
          '# Vérifier ASN / organisation',
          'whois 1.2.3.4 | grep -E "OrgName|Country|CIDR"',
        ],
      },
      {
        label: 'Protocoles inhabituels',
        items: [
          '# Trafic FTP sortant',
          "cat conn.log | zeek-cut id.resp_p proto | awk '$1==21 || $1==20 {print \"FTP: \"$0}' | head",
          '# Trafic DNS en volume (DNS exfil)',
          'cat dns.log | zeek-cut id.orig_h query | awk \'{count[$1]++} END{for(h in count) if(count[h]>200) print count[h], h}\' | sort -rn',
          '# ICMP avec large payload',
          "tshark -r cap.pcap -Y 'icmp && data.len > 64' -T fields -e ip.src -e ip.dst -e data.len",
          '# SMTP sortant (exfil via email)',
          "cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | awk '$3==25 || $3==587 || $3==465'",
        ],
      },
    ],
    iocs: [
      'Upload > 100 MB vers IP externe non-business',
      'Connexion HTTPS vers mega.nz, dropbox.com depuis serveur (rclone)',
      'SMTP sortant depuis endpoint non-serveur mail',
      'FTP/SFTP sortant hors zone DMZ',
      'DNS query volume > 1000/min depuis même source',
      'Trafic ICMP avec payload > 100 bytes',
    ],
  },
  {
    id: 'firewall-proxy-logs',
    title: 'Logs Firewall & Proxy Web',
    icon: '🛡️',
    category: 'Infrastructure',
    summary: "Les logs firewall et proxy sont souvent la seule source réseau disponible dans les enquêtes. Ils permettent de retracer les connexions, identifier les C2 et quantifier les exfiltrations.",
    content: [
      {
        label: 'Firewall — Analyse des deny',
        items: [
          '# Top destinations bloquées (tente de contacter C2)',
          'grep "DENY\\|BLOCK\\|DROP" firewall.log | awk \'{print $dst}\' | sort | uniq -c | sort -rn | head 20',
          '# Flux internes bloqués (mouvement latéral)',
          'grep "DENY" firewall.log | grep -E "src=10\\.|dst=10\\."',
          '# Ports inhabituels sortants',
          'grep "ALLOW" firewall.log | awk \'{print $dport}\' | sort | uniq -c | sort -rn | grep -vE "^.*443|^.*80|^.*53"',
        ],
      },
      {
        label: 'Proxy Web — Analyse',
        items: [
          '# URLs avec paramètres encodés Base64 (C2)',
          'grep "base64\\|%2F%2F\\|%3D%3D" proxy.log | head 20',
          '# Téléchargements de binaires via proxy',
          'grep -E "application/octet-stream|application/x-executable|application/x-msdownload" proxy.log',
          '# Sites catégorisés "Uncategorized" ou "Newly registered"',
          '# (configurable dans proxy Bluecoat, Zscaler, ForcePoint)',
          '# Accès à cloud non autorisé (MEGA, Dropbox, WeTransfer)',
          'grep -iE "mega\\.nz|transfer\\.sh|wetransfer\\.com|gofile\\.io" proxy.log',
        ],
      },
      {
        label: 'Corrélation Proxy + EDR',
        items: [
          '# Extraire IPs contactées depuis proxy pour un endpoint',
          'grep "10.1.2.3" proxy.log | awk \'{print $dst}\' | sort | uniq > endpoint_destinations.txt',
          '# Croiser avec processus réseau de l\'EDR',
          '# Identifier quel processus a généré chaque connexion',
          '# Timeline : heure première connexion externe + heure alerte EDR',
        ],
      },
    ],
    iocs: [
      'Connexion vers domaine sans catégorie (proxy uncategorized)',
      'User-Agent absent ou générique (curl/7.x, python-requests)',
      'GET /update?id= ou POST /gate.php (patterns C2)',
      'Téléchargement .exe/.dll depuis domaine récent',
      'Accès MEGA, WeTransfer, Anonfiles depuis endpoint',
    ],
  },
  {
    id: 'network-forensics-tools',
    title: 'Outils d\'Analyse Réseau — Référence Rapide',
    icon: '🔧',
    category: 'Outils',
    summary: "Référence des commandes essentielles pour l'analyse forensique réseau : tshark, tcpdump, zeek, nfdump, ntopng, NetworkMiner.",
    content: [
      {
        label: 'tcpdump — Capture et filtrage',
        items: [
          '# Capturer trafic d\'une IP',
          'tcpdump -i eth0 -w capture.pcap host 192.168.1.100',
          '# Capturer trafic HTTP/HTTPS',
          'tcpdump -i eth0 -w web.pcap port 80 or port 443',
          '# Capturer trafic DNS',
          'tcpdump -i any -w dns.pcap port 53',
          '# Capturer trafic SMB + Kerberos',
          'tcpdump -i eth0 -w lateral.pcap port 445 or port 88 or port 135',
          '# Afficher en temps réel (sans écriture)',
          'tcpdump -i eth0 -n -v port 4444',
        ],
      },
      {
        label: 'tshark — Extraction avancée',
        items: [
          '# Extraire credentials HTTP Basic',
          "tshark -r cap.pcap -Y 'http.authorization' -T fields -e http.authorization",
          '# Extraire fichiers transférés (HTTP)',
          'tshark -r cap.pcap --export-objects http,/tmp/extracted_files/',
          '# Afficher toutes les connexions TCP établies',
          "tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq",
          '# Statistiques SSL/TLS',
          'tshark -r cap.pcap -q -z ssl,stat',
          '# Extraire fichiers SMB2',
          'tshark -r cap.pcap --export-objects smb,/tmp/smb_files/',
        ],
      },
      {
        label: 'NetworkMiner — Analyse passive',
        items: [
          '# NetworkMiner (GUI) — reconstruction automatique des fichiers transférés',
          '# Ouvre PCAP → onglet Files = tous les fichiers extraits',
          '# Onglet Credentials = credentials capturés',
          '# Onglet DNS = requêtes/réponses DNS',
          '# Onglet Sessions = toutes les sessions TCP/UDP',
          '# Export → CSV pour intégration SIEM',
        ],
      },
      {
        label: 'nfdump / nfcapd — NetFlow Analysis',
        items: [
          '# Lire NetFlow exports',
          'nfdump -R /var/netflow/ -o long "src ip 192.168.1.100"',
          '# Top talkers par bytes',
          'nfdump -R /var/netflow/ -s record/bytes -n 20',
          '# Connexions vers port spécifique',
          'nfdump -R /var/netflow/ "dst port 4444"',
          '# Timeline connexions d\'un host',
          'nfdump -R /var/netflow/ "src ip 10.0.0.5" -o csv | sort',
        ],
      },
    ],
    iocs: [],
  },
];

const CATEGORIES = ['Tous', 'PCAP', 'C2 Detection', 'DNS', 'Lateral Movement', 'Exfiltration', 'Infrastructure', 'Outils'];

function TopicCard({ topic, search }) {
  const T = useTheme();
  const [open, setOpen] = useState(false);

  const matches = useMemo(() => {
    if (!search) return true;
    const q = search.toLowerCase();
    return topic.title.toLowerCase().includes(q) ||
      topic.summary.toLowerCase().includes(q) ||
      topic.content.some(s => s.items.some(i => i.toLowerCase().includes(q))) ||
      topic.iocs.some(i => i.toLowerCase().includes(q));
  }, [search, topic]);

  if (!matches) return null;

  return (
    <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginBottom: 10 }}>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left"
        style={{ padding: '12px 16px', background: 'var(--fl-card)', border: 'none', cursor: 'pointer', display: 'block', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 15 }}>{topic.icon}</span>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 12, color: T.text }}>{topic.title}</span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, padding: '1px 6px', borderRadius: 3,
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)' }}>
              {topic.category}
            </span>
          </div>
          {open ? <ChevronDown size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} /> : <ChevronRight size={13} style={{ color: T.dim, flexShrink: 0, marginTop: 2 }} />}
        </div>
        <p style={{ fontSize: 11, marginTop: 5, marginLeft: 22, color: T.muted, fontFamily: 'monospace', lineHeight: 1.5 }}>{topic.summary}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '14px 16px' }}>
          {topic.content.map((section, si) => (
            <div key={si} style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>{section.label}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {section.items.map((cmd, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '5px 9px', borderRadius: 4,
                    background: T.panel, border: '1px solid var(--fl-border)' }}>
                    <code style={{ fontFamily: 'monospace', fontSize: 11, color: cmd.startsWith('#') ? T.dim : 'var(--fl-ok)', wordBreak: 'break-all', flex: 1, lineHeight: 1.5 }}>{cmd}</code>
                    {!cmd.startsWith('#') && <CopyBtn text={cmd} />}
                  </div>
                ))}
              </div>
            </div>
          ))}

          {topic.iocs && topic.iocs.length > 0 && (
            <div>
              <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)', marginBottom: 7 }}>IOCs réseau</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {topic.iocs.map((ioc, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 11, fontFamily: 'monospace', padding: '5px 8px', borderRadius: 4,
                    background: 'color-mix(in srgb, var(--fl-danger) 5%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--fl-danger) 18%, transparent)', color: T.text }}>
                    <AlertTriangle size={10} style={{ color: 'var(--fl-danger)', flexShrink: 0, marginTop: 2 }} />
                    <span>{ioc}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function NetworkForensicsDoc({ search }) {
  const T = useTheme();
  const [catFilter, setCatFilter] = useState('Tous');

  const filtered = useMemo(() => {
    return TOPICS.filter(t => {
      if (catFilter !== 'Tous' && t.category !== catFilter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return t.title.toLowerCase().includes(q) ||
        t.summary.toLowerCase().includes(q) ||
        t.content.some(s => s.items.some(i => i.toLowerCase().includes(q))) ||
        t.iocs.some(i => i.toLowerCase().includes(q));
    });
  }, [search, catFilter]);

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      <div style={{ marginBottom: 14 }}>
        <h1 style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: T.text, marginBottom: 3 }}>Forensique Réseau</h1>
        <p style={{ fontFamily: 'monospace', fontSize: 11, color: T.muted }}>
          {search || catFilter !== 'Tous'
            ? `${filtered.length} section${filtered.length !== 1 ? 's' : ''} trouvée${filtered.length !== 1 ? 's' : ''}`
            : `${TOPICS.length} sections — PCAP · C2 · DNS · Lateral Movement · Exfiltration · Firewall · Outils`}
        </p>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 16 }}>
        {CATEGORIES.map(c => {
          const active = catFilter === c;
          const count = c === 'Tous' ? TOPICS.length : TOPICS.filter(t => t.category === c).length;
          return (
            <button key={c} onClick={() => setCatFilter(c)}
              style={{
                fontFamily: 'monospace', fontSize: 10, padding: '3px 8px', borderRadius: 4,
                cursor: 'pointer', border: '1px solid',
                background: active ? 'color-mix(in srgb, var(--fl-warn) 18%, transparent)' : 'var(--fl-card)',
                color: active ? 'var(--fl-warn)' : T.dim,
                borderColor: active ? 'color-mix(in srgb, var(--fl-warn) 45%, transparent)' : T.border,
              }}>
              {c} ({count})
            </button>
          );
        })}
      </div>

      {filtered.map(t => <TopicCard key={t.id} topic={t} search={search} />)}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.muted }}>
          <p style={{ fontFamily: 'monospace', fontSize: 13 }}>Aucun contenu ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
