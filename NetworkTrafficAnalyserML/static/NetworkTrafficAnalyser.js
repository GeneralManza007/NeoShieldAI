let globalPacketData = [];
const blockedIPs = new Set();
const blockedSignatures = new Set();
let editedPackets = {};
let isEditingPacket = false;
let selectedPacketId = null;
let flowData = [];
let hostRiskChart = null;

let responsePolicies = [];
let actionLogs = [];
let quarantinedHosts = new Set();
let nextPolicyId = 1;
let nextLogId = 1;

let assets = [];
let nextAssetId = 1;

let uebaData = {}; 
const UEBA_WINDOW_MS = 5 * 60 * 1000; 
const UEBA_BASELINE_MS = 24 * 60 * 60 * 1000; 
const UEBA_MIN_SAMPLES = 10; 


const UEBA_THRESHOLDS = {
    trafficVolume: 2.0,    
    newDestinations: 3,     
    rareProtocols: 1,        
    countryChange: 2         
};

let sparklineCharts = {};

let pendingActions = [];  
let nextPendingId = 1;

let timelineEvents = [];
const hostStages = new Map(); 
let lastPacketCount = 0;
let lastPacketTime = Date.now();
let hostPreviousStatus = new Map();
let analyticsProtocolChart, analyticsTrafficChart, analyticsPortsChart, analyticsRiskChart;
let geoViewVisible = false;
let isUpdatingGeo = false;
let geoThreatChart, geoSourceBarChart, geoRiskTimeline, sankeyPlot;

let lastManualAction = null;

let cases = [];
let nextCaseId = 1;

let incidents = [];
let nextIncidentId = 1;

let iocs = [];
let nextIocId = 1;

let rules = [];
let nextRuleId = 1;

const DEFAULT_POLICY = {
    id: null,
    name: '',
    description: '',
    enabled: true,
    conditions: {
        confidenceMin: 0,
        confidenceMax: 100,
        severities: ['low', 'medium', 'high', 'critical'],
        eventTypes: [],
    },
    actions: [], 
    autoExecute: true, 
    cooldown: 300, 
    expiresAfter: 3600,
};

const POLICY_TEMPLATES = [
    {
        icon: '🎯',
        name: 'High Confidence IOC',
        desc: 'Block IP & create case on high-confidence IOC matches',
        actions: [
            { type: 'block_ip', parameters: { targetIp: '{{src}}' } },
            { type: 'create_case', parameters: { caseTitle: 'IOC Match: {{eventType}}' } }
        ],
        conditions: {
            confidenceMin: 80,
            confidenceMax: 100,
            severities: ['high', 'critical'],
            eventTypes: ['IOC Match']
        },
        priority: 1,
        autoExecute: true,
        simulateOnly: false
    },
    {
        icon: '💀',
        name: 'Critical C2',
        desc: 'Quarantine host & create case on C2 beaconing',
        actions: [
            { type: 'quarantine_host', parameters: { targetHost: '{{src}}' } },
            { type: 'create_case', parameters: { caseTitle: 'C2 Activity: {{src}}' } }
        ],
        conditions: {
            confidenceMin: 70,
            confidenceMax: 100,
            severities: ['critical'],
            eventTypes: ['Beaconing to Malicious Host', 'Potential C2 Activity']
        },
        priority: 1,
        autoExecute: true,
        simulateOnly: false
    },
    {
        icon: '🔓',
        name: 'Brute Force',
        desc: 'Raise severity & notify analyst on brute force',
        actions: [
            { type: 'raise_severity', parameters: { newSeverity: 'critical' } },
            { type: 'send_notification', parameters: { channel: 'dashboard' } }
        ],
        conditions: {
            confidenceMin: 60,
            confidenceMax: 100,
            severities: ['medium', 'high'],
            eventTypes: ['Brute Force Attempt']
        },
        priority: 2,
        autoExecute: true,
        simulateOnly: false
    },
    {
        icon: '🌍',
        name: 'Suspicious Geo',
        desc: 'Block IP & create case for high-risk countries',
        actions: [
            { type: 'block_ip', parameters: { targetIp: '{{src}}' } },
            { type: 'create_case', parameters: { caseTitle: 'Suspicious Geo: {{src}} → {{dst}}' } }
        ],
        conditions: {
            confidenceMin: 50,
            confidenceMax: 100,
            severities: ['medium', 'high', 'critical'],
            eventTypes: ['Suspicious Geolocation']
        },
        priority: 2,
        autoExecute: true,
        simulateOnly: false
    },
    {
        icon: '📦',
        name: 'Data Exfiltration',
        desc: 'Quarantine host & notify on exfiltration',
        actions: [
            { type: 'quarantine_host', parameters: { targetHost: '{{src}}' } },
            { type: 'send_notification', parameters: { channel: 'dashboard' } }
        ],
        conditions: {
            confidenceMin: 65,
            confidenceMax: 100,
            severities: ['high', 'critical'],
            eventTypes: ['Possible Data Exfiltration', 'Data Exfiltration']
        },
        priority: 1,
        autoExecute: true,
        simulateOnly: false
    }
];

const ACTION_TYPES = [
    'block_ip',
    'quarantine_host',
    'add_ioc',
    'create_case',
    'send_notification',
    'raise_severity',
    'kill_connection', 
];

function loadIncidents() {
    try {
        const stored = localStorage.getItem('neoShieldIncidents');
        if (stored) {
            incidents = JSON.parse(stored);
            
            incidents = incidents.map(inc => ({
                ...inc,
                hosts: new Set(inc.hosts || []),
                alertIds: new Set(inc.alertIds || []),
                attackStages: new Set(inc.attackStages || []),
            }));
            nextIncidentId = incidents.reduce((max, i) => Math.max(max, i.id), 0) + 1;
        } else {
            incidents = [];
            nextIncidentId = 1;
        }
    } catch (e) {
        incidents = [];
        nextIncidentId = 1;
    }
}

function saveIncidents() {
    try {
        const serialized = incidents.map(inc => ({
            ...inc,
            hosts: [...inc.hosts],
            alertIds: [...inc.alertIds],
            attackStages: [...inc.attackStages],
        }));
        localStorage.setItem('neoShieldIncidents', JSON.stringify(serialized));
    } catch (e) {}
}



function computeAIRiskScore(alert) {
    const src = alert.src;
    let score = 0;
    const breakdown = [];

    
    const mlConf = alert.confidence || 50;
    const mlContrib = mlConf * 0.30;
    score += mlContrib;
    breakdown.push({ reason: 'ML Confidence', contribution: mlContrib });

    
    const ueba = uebaData[src]?.score || 0;
    const uebaContrib = Math.min(ueba * 0.20, 20);
    score += uebaContrib;
    breakdown.push({ reason: 'UEBA Anomaly', contribution: uebaContrib });

    
    const hostRisk = mlInfoMap.get(src)?.score || 0;
    const hostContrib = Math.min(hostRisk * 0.20, 20);
    score += hostContrib;
    breakdown.push({ reason: 'Historical Host Risk', contribution: hostContrib });

    
    let iocContrib = 0;
    const srcInIOC = iocs.some(i => i.value === src);
    const dstInIOC = alert.dst && iocs.some(i => i.value === alert.dst);
    if (alert.evidence?.iocType || srcInIOC || dstInIOC) {
        iocContrib = 15;
        breakdown.push({ reason: 'IOC Match', contribution: iocContrib });
        score += iocContrib;
    }

    
    let mitreContrib = 0;
    if (alert.mitre) {
        const tactic = MITRE_TECHNIQUES[alert.mitre]?.tactic || '';
        const tacticWeights = {
            'Reconnaissance': 5,
            'Initial Access': 10,
            'Credential Access': 12,
            'Command & Control': 15,
            'Exfiltration': 15
        };
        mitreContrib = tacticWeights[tactic] || 5;
        breakdown.push({ reason: `MITRE ${alert.mitre} (${tactic})`, contribution: mitreContrib });
        score += mitreContrib;
    }

    
    let assetContrib = 0;
    const asset = getAssetByIdentifier(src);
    if (asset) {
        const criticalityWeights = {
            'Low': 2,
            'Medium': 5,
            'High': 8,
            'Critical': 10
        };
        assetContrib = criticalityWeights[asset.criticality] || 0;
        breakdown.push({ reason: `Asset Criticality (${asset.criticality})`, contribution: assetContrib });
        score += assetContrib;
    }

    
    const priorAlerts = timelineEvents.filter(e => e.src === src && e.id !== alert.id).length;
    if (priorAlerts > 0) {
        const freqContrib = Math.min(priorAlerts * 2, 10);
        breakdown.push({ reason: `${priorAlerts} prior alerts for host`, contribution: freqContrib });
        score += freqContrib;
    }

    
    const hasAuto = actionLogs.some(l => l.alertId === alert.id && l.success);
    if (hasAuto) {
        const autoContrib = 5;
        breakdown.push({ reason: 'Automated action triggered', contribution: autoContrib });
        score += autoContrib;
    }

    
    score = Math.min(score, 100);

    
    const totalContrib = breakdown.reduce((sum, item) => sum + item.contribution, 0);
    if (totalContrib > 0) {
        const scale = score / totalContrib;
        breakdown.forEach(item => {
            item.contribution = Math.round(item.contribution * scale);
        });
        
        let sum = breakdown.reduce((s, item) => s + item.contribution, 0);
        if (sum !== score && breakdown.length > 0) {
            const diff = score - sum;
            breakdown[0].contribution += diff;
        }
    } else {
        breakdown.push({ reason: 'Base detection', contribution: score });
    }

    
    let level = 'Informational';
    if (score >= 95) level = 'Critical';
    else if (score >= 80) level = 'High';
    else if (score >= 60) level = 'Elevated';
    else if (score >= 40) level = 'Moderate';
    else if (score >= 20) level = 'Low';

    
    const topFactors = breakdown.slice().sort((a, b) => b.contribution - a.contribution).slice(0, 3);
    const reasonParts = [];
    if (topFactors.length) {
        topFactors.forEach(f => {
            reasonParts.push(`${f.reason} contributed ${f.contribution} points`);
        });
    }
    
    if (alert.eventType.includes('Beaconing')) reasonParts.push('Beaconing activity indicates potential C2');
    if (alert.eventType.includes('Exfiltration')) reasonParts.push('Data exfiltration pattern detected');
    if (alert.eventType.includes('Brute Force')) reasonParts.push('Brute force attempts observed');
    if (alert.eventType.includes('IOC')) reasonParts.push('Indicator of Compromise matched');
    if (alert.src) {
        const asset = getAssetByIdentifier(alert.src);
        if (asset && asset.criticality === 'Critical') reasonParts.push('Asset is classified as Critical');
    }
    const reasoning = reasonParts.length ? reasonParts.join('. ') + '.' : 'Standard heuristic detection.';

    return {
        score: Math.round(score),
        level: level,
        breakdown: breakdown,
        reasoning: reasoning
    };
}

function generateRecommendedActions(alert) {
    const evidence = alert.evidence || {};
    const type = alert.eventType;
    let summary = '';
    let actions = [];

    
    if (type === 'Beaconing' || type === 'Beaconing to Malicious Host') {
        const { packetCount, avgIntervalSec, isIOC } = evidence;
        const isRegular = avgIntervalSec && avgIntervalSec < 120;
        const isHighVolume = packetCount && packetCount > 20;

        if (isIOC && isRegular) {
            summary = `The host is likely compromised and is communicating with a known command‑and‑control server at regular intervals. Immediate containment is advised.`;
            actions = [
                'Isolate the host from the network immediately.',
                'Capture memory and disk images for forensic analysis.',
                'Block the malicious destination IP at the firewall.',
                'Review authentication logs for any lateral movement.',
                'Check for persistence mechanisms (scheduled tasks, services).'
            ];
        } else if (isRegular) {
            summary = `The host exhibits beaconing behaviour to an external IP, suggesting possible C2 activity. Further investigation is required.`;
            actions = [
                'Block the destination IP if not a known legitimate service.',
                'Enhance monitoring for this host for the next 24 hours.',
                'Collect network logs to identify any data exfiltration.',
                'Consider placing the host in a quarantine VLAN.'
            ];
        } else {
            summary = `Suspicious periodic communication detected, but the pattern is not strong enough to confirm C2.`;
            actions = [
                'Review the destination IP and its reputation.',
                'Monitor the host for any other anomalies (UEBA, IOCs).',
                'Check if the destination is a known cloud or CDN service.'
            ];
        }
    }

    
    else if (type.includes('Port Scan')) {
        const { targetCount, portCount } = evidence;
        if (targetCount > 25 || portCount > 30) {
            summary = `Aggressive port scanning detected, likely reconnaissance for an impending attack.`;
            actions = [
                'Block the source IP immediately.',
                'Check if the source is a legitimate security scanner.',
                'Review firewall rules to ensure no unnecessary open ports.',
                'Enable enhanced logging on all critical assets.',
                'Consider implementing an IPS rule to drop traffic from that source.'
            ];
        } else {
            summary = `Port scanning activity detected – may indicate a misconfigured service or early‑stage reconnaissance.`;
            actions = [
                'Identify the source host and determine if it is an authorised scanner.',
                'Restrict outbound scanning from internal hosts.',
                'Monitor the source for further scanning or exploit attempts.'
            ];
        }
    }

    
    else if (type === 'Brute Force Attempt') {
        const { attempts, targetPort, isSensitivePort } = evidence;
        if (isSensitivePort && attempts > 50) {
            summary = `Heavy brute‑force attack against a sensitive port (${targetPort}) – active credential compromise attempt.`;
            actions = [
                'Block the source IP at the perimeter.',
                'Require multi‑factor authentication for the targeted service.',
                'Review account lockout policies and failed login logs.',
                'Alert the affected asset owner.',
                'Consider enabling CAPTCHA or rate‑limiting for the service.'
            ];
        } else {
            summary = `Moderate number of login attempts against port ${targetPort} – may be a misconfiguration or automated scanning.`;
            actions = [
                'Monitor the source IP for further attempts.',
                'Check if the attempts are coming from a trusted internal service.',
                'Implement temporary IP blacklisting after 5 failures.'
            ];
        }
    }

    
    else if (type === 'Possible Data Exfiltration' || type === 'Data Exfiltration') {
        const { megabytesSent } = evidence;
        if (megabytesSent > 100) {
            summary = `Large‑scale data exfiltration detected – potential data breach in progress.`;
            actions = [
                'Isolate the source host immediately.',
                'Block outbound traffic to the suspicious destination(s).',
                'Initiate incident response and data breach notification procedures.',
                'Capture network traffic for forensic investigation.',
                'Check for any unusual user accounts or scheduled data transfer jobs.'
            ];
        } else {
            summary = `Moderate outbound data volume to external destinations – may be legitimate, but should be investigated.`;
            actions = [
                'Review the destination IPs and their reputation.',
                'Check if the data transfer aligns with business operations (backups, updates).',
                'Increase logging for the source host and monitor for future exfiltration.'
            ];
        }
    }

    
    else if (type === 'Suspicious Geolocation') {
        const { countryCode } = evidence;
        const isHighRisk = countryCode === 'KP' || countryCode === 'RU';
        if (isHighRisk) {
            summary = `Communication with a high‑risk country (${countryCode}) – may indicate geopolitical threat activity.`;
            actions = [
                'Block traffic to/from that country if not required for business.',
                'Review the user’s account for any compromise indicators.',
                'Enhance monitoring for the source host.',
                'Check for any other assets communicating with that country.'
            ];
        } else {
            summary = `Connection to a country classified as suspicious, but not extreme risk.`;
            actions = [
                'Verify if the destination is a legitimate business partner.',
                'Monitor for any unusual data transfer or authentication attempts.',
                'Consider adding the destination to a watchlist for further observation.'
            ];
        }
    }

    
    else if (type.includes('IOC Match')) {
        const { iocType, iocValue } = evidence;
        summary = `Indicator of Compromise (${iocType}) detected – the host has contacted a known malicious entity.`;
        actions = [
            'Isolate the host immediately if it is critical.',
            'Block the IOC value (IP/domain/hash) across all security controls.',
            'Perform a thorough scan of the host for malware.',
            'Check for other hosts that may have communicated with the same IOC.',
            'Escalate to incident response team.'
        ];
    }

    
    else if (type.includes('Custom Rule Match')) {
        const { ruleName } = evidence;
        summary = `Custom detection rule "${ruleName}" triggered – behaviour matches predefined suspicious criteria.`;
        actions = [
            'Review the rule conditions to ensure accuracy.',
            'Check the alert details to validate whether it is a true positive.',
            'If true positive, follow the appropriate response playbook.',
            'Consider tuning the rule to reduce false positives.'
        ];
    }

    
    else if (type === 'Host Risk Change') {
        const { newStatus, score } = evidence;
        if (newStatus === 'Block' || score > 80) {
            summary = `Host risk escalated to high – the host is now considered compromised.`;
            actions = [
                'Isolate the host from the network.',
                'Initiate full malware scan and forensic capture.',
                'Review all recent activity from this host.',
                'Notify the asset owner and security team.'
            ];
        } else if (newStatus === 'Alert') {
            summary = `Host risk score increased – the host shows suspicious behaviour, but not yet confirmed compromised.`;
            actions = [
                'Increase monitoring on this host.',
                'Check for any associated alerts or IOCs.',
                'Consider placing the host in a quarantine VLAN pending investigation.'
            ];
        } else {
            summary = `Host risk level fluctuated – this may be due to normal network activity.`;
            actions = [
                'Monitor the host for any further changes.',
                'Review if any security policies were applied recently.'
            ];
        }
    }

    
    else if (type.includes('Multi‑Stage')) {
        const { stages } = evidence;
        summary = `A multi‑stage attack chain has been observed on the host – from reconnaissance to potential compromise.`;
        actions = [
            'Immediate isolation of the affected host.',
            'Perform a full forensic acquisition (memory, disk, logs).',
            'Identify the entry point and patch the vulnerability.',
            'Check for lateral movement to other hosts.',
            'Engage the incident response team.'
        ];
    }

    
    else {
        summary = `An alert has been generated. Further investigation is recommended.`;
        actions = [
            'Review the alert details and surrounding context.',
            'Check for any related alerts or IOCs.',
            'If the alert appears to be a false positive, mark it and update the detection logic.',
            'For true positives, initiate standard incident response procedures.'
        ];
    }

    
    const uniqueActions = [...new Set(actions)];
    const topActions = uniqueActions.slice(0, 5);

    return { summary, actions: topActions };
}


function getAttackStage(alert) {
    const mitre = alert.mitre || null;
    const type = alert.eventType;
    let tactic = 'Unknown';
    let technique = mitre || 'Unknown';
    let name = '';
    let description = '';

    if (mitre && MITRE_TECHNIQUES[mitre]) {
        const info = MITRE_TECHNIQUES[mitre];
        tactic = info.tactic;
        name = info.name;
        description = `This behaviour aligns with MITRE ${mitre} (${name}).`;
    } else {
        
        const tacticMap = {
            'Horizontal Port Scan': 'Reconnaissance',
            'Vertical Port Scan': 'Reconnaissance',
            'Brute Force Attempt': 'Credential Access',
            'Beaconing': 'Command & Control',
            'Beaconing to Malicious Host': 'Command & Control',
            'Potential C2 Activity': 'Command & Control',
            'DNS Tunneling': 'Command & Control',
            'Data Exfiltration': 'Exfiltration',
            'Possible Data Exfiltration': 'Exfiltration',
            'Tor Connection': 'Command & Control',
            'Suspicious Geolocation': 'Reconnaissance',
            'Multi-Stage Attack Chain': 'Initial Access',
            'Suspicious Activity Pattern': 'Reconnaissance'
        };
        tactic = tacticMap[type] || 'Unknown';
        description = `This behaviour is consistent with ${tactic} activities.`;
    }

    return { tactic, technique, name, description };
}

function getNextBehaviour(alert) {
    const tactic = getAttackStage(alert).tactic;
    const nextMap = {
        'Reconnaissance': [
            'Initial Access – exploit vulnerable service',
            'Credential Access – brute force or phishing'
        ],
        'Initial Access': [
            'Command & Control – establish persistent channel',
            'Privilege Escalation'
        ],
        'Credential Access': [
            'Lateral Movement – use stolen credentials',
            'Persistence – create backdoor accounts'
        ],
        'Command & Control': [
            'Exfiltration – data extraction',
            'Lateral Movement – expand control',
            'Impact – ransomware deployment'
        ],
        'Exfiltration': [
            'Impact – data leak or ransomware',
            'Cover-up – log deletion'
        ],
        'Unknown': [
            'Further investigation required'
        ]
    };
    return nextMap[tactic] || nextMap['Unknown'];
}

function getPotentialImpact(alert) {
    const severity = alert.severity || 'low';
    const confidence = alert.confidence || 50;
    const reasons = [];
    let level = 'Low';

    
    const type = alert.eventType;
    const evidence = alert.evidence || {};

    if (severity === 'critical' || confidence > 90) {
        level = 'High';
        reasons.push('Alert severity is critical or confidence is very high.');
    } else if (severity === 'high' || confidence > 70) {
        level = 'Medium';
        reasons.push('Alert severity is high or confidence is above 70%.');
    } else {
        level = 'Low';
        reasons.push('Alert severity and confidence are moderate or low.');
    }

    
    if (type.includes('Exfiltration')) {
        reasons.push('Data exfiltration indicates active data breach.');
        if (level === 'Low') level = 'Medium';
    }
    if (type.includes('C2') || type.includes('Beaconing')) {
        reasons.push('C2 communication suggests persistent compromise.');
        if (level !== 'High') level = 'High';
    }
    if (type.includes('Brute Force')) {
        reasons.push('Brute force attempts may lead to credential compromise.');
        if (level === 'Low') level = 'Medium';
    }
    if (type.includes('Port Scan')) {
        reasons.push('Reconnaissance activity may precede a targeted attack.');
        if (level === 'Low') level = 'Medium';
    }
    if (evidence.isIOC || evidence.iocType) {
        reasons.push('IOC match confirms known malicious indicator.');
        if (level !== 'High') level = 'High';
    }

    
    if (reasons.length === 0) {
        reasons.push('Based on current evidence, the potential impact is limited.');
    }

    return { level, reasons };
}


function predictNextAttackStage(alert) {
    const src = alert.src;
    const hostEntry = src ? hostStages.get(src) : null;
    const stages = hostEntry ? hostEntry.stages : new Map();
    const completedPhases = new Set();
    for (const [stage, _] of stages) {
        const phase = PHASE_MAP[stage];
        if (phase) completedPhases.add(phase);
    }
    
    const currentStage = STAGE_MAP[alert.eventType] || null;
    if (currentStage) {
        const phase = PHASE_MAP[currentStage];
        if (phase) completedPhases.add(phase);
    }

    
    let currentPhase = null;
    for (const phase of PHASE_ORDER) {
        if (completedPhases.has(phase)) {
            currentPhase = phase;
        }
    }

    
    if (!currentPhase) {
        currentPhase = 'Reconnaissance';
    }

    
    const currentIndex = PHASE_ORDER.indexOf(currentPhase);
    let nextPhase = null;
    if (currentIndex < PHASE_ORDER.length - 1) {
        nextPhase = PHASE_ORDER[currentIndex + 1];
    } else {
        nextPhase = 'Complete'; 
    }

    
    
    
    
    const progress = (completedPhases.size / PHASE_ORDER.length) * 100;
    let probability = 0;
    if (nextPhase === 'Complete') {
        probability = 100;
    } else {
        
        probability = Math.min(progress + 20, 80); 
        
        const confidenceBoost = (alert.confidence || 50) / 100 * 20; 
        probability = Math.min(probability + confidenceBoost, 95);
        
        probability = Math.max(probability, 10);
    }

    
    const reasoning = [];
    if (completedPhases.size > 0) {
        reasoning.push(`Completed stages: ${Array.from(completedPhases).join(' → ')}.`);
    } else {
        reasoning.push('No previous stages detected for this host.');
    }
    reasoning.push(`Current stage estimated as ${currentPhase}.`);
    if (nextPhase !== 'Complete') {
        reasoning.push(`The attacker is likely to progress to ${nextPhase} next.`);
    } else {
        reasoning.push('All stages in the kill chain appear to be completed.');
    }
    if (alert.confidence) {
        reasoning.push(`Alert confidence (${alert.confidence}%) supports this prediction.`);
    }

    return {
        currentPhase,
        nextPhase,
        probability: Math.round(probability),
        completedPhases: Array.from(completedPhases),
        progress,
        reasoning
    };
}

const lastAlert = new Map();
function generateAlertExplanation(alert) {
    const evidence = alert.evidence || {};
    const type = alert.eventType;
    const explanation = [];
    const confidenceBreakdown = [];
    const whyNot100 = [];
    let summary = '';
    let evidenceCount = 0;

    function addBreakdown(reason, contribution) {
        confidenceBreakdown.push({ reason, contribution });
    }

    
    function countIndicators() {
        let count = 0;
        if (explanation.length) count += explanation.length;
        if (evidence.mitre) count += 1;
        if (evidence.isIOC || evidence.iocType) count += 1;
        return count;
    }

    
    if (type === 'Beaconing' || type === 'Beaconing to Malicious Host') {
        const { packetCount, avgIntervalSec, varianceRatio, durationSec, isIOC, destinationPort } = evidence;
        if (packetCount) {
            explanation.push(`The host communicated with the same destination ${packetCount} times.`);
            addBreakdown(`High packet count (${packetCount})`, Math.min(packetCount * 1.5, 25));
        }
        if (avgIntervalSec) {
            explanation.push(`The average interval between communications was ${avgIntervalSec} seconds.`);
            addBreakdown(`Consistent interval (${avgIntervalSec}s)`, 20);
        }
        if (varianceRatio !== undefined && varianceRatio < 0.15) {
            explanation.push(`Intervals were highly regular (variance ratio ${varianceRatio.toFixed(2)}), indicating beaconing.`);
            addBreakdown(`Low variance (${varianceRatio.toFixed(2)})`, 20);
        }
        if (durationSec && durationSec > 120) {
            explanation.push(`The communication lasted ${durationSec} seconds, showing persistence.`);
            addBreakdown(`Long duration (${durationSec}s)`, 15);
        }
        if (isIOC) {
            explanation.push(`The destination IP matched a known Indicator of Compromise.`);
            addBreakdown(`IOC match`, 15);
        }
        if (destinationPort && ![80, 443, 53].includes(destinationPort)) {
            explanation.push(`Traffic used non‑standard port ${destinationPort}.`);
            addBreakdown(`Non‑standard port (${destinationPort})`, 10);
        }
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        if (!isIOC) whyNot100.push("The destination IP was not previously known to be malicious.");
        if (packetCount && packetCount < 10) whyNot100.push("Relatively few communication events observed.");

        summary = `The detection engine identified behaviour consistent with command-and-control beaconing. The host repeatedly communicated with the same destination using highly regular intervals.`;
        evidenceCount = countIndicators();
    }

    
    else if (type.includes('Port Scan')) {
        const { targetCount, portCount, isBlacklisted } = evidence;
        if (type === 'Horizontal Port Scan') {
            explanation.push(`The host scanned ${targetCount} distinct destination IPs.`);
            addBreakdown(`Many targets (${targetCount})`, 25);
        } else {
            explanation.push(`The host probed ${portCount} different ports.`);
            addBreakdown(`Many ports (${portCount})`, 25);
        }
        explanation.push(`Only ${portCount} different ports were used.`);
        addBreakdown(`Low port diversity`, 20);
        if (isBlacklisted) {
            explanation.push(`The source IP was already blacklisted.`);
            addBreakdown(`Blacklisted source`, 20);
        }
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("Scanning may be a legitimate security tool or misconfiguration.");
        summary = `The system detected a port scan pattern: the host attempted to connect to multiple destinations or ports, which is typical of reconnaissance.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Brute Force Attempt') {
        const { attempts, targetPort, isSensitivePort } = evidence;
        explanation.push(`The source made ${attempts} connection attempts to the target in one minute.`);
        addBreakdown(`High attempt rate (${attempts})`, 30);
        if (isSensitivePort) {
            explanation.push(`Targeted port ${targetPort} is sensitive (e.g., SSH, RDP, SQL).`);
            addBreakdown(`Sensitive port (${targetPort})`, 25);
        }
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("High attempt rate could be a misconfigured service or application.");
        summary = `The detection engine identified a brute force attempt: a large number of authentication attempts were observed against a sensitive port.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Possible Data Exfiltration' || type === 'Data Exfiltration') {
        const { megabytesSent, windowMinutes } = evidence;
        explanation.push(`The host sent ${megabytesSent.toFixed(1)} MB of data to external destinations in the last ${windowMinutes} minutes.`);
        addBreakdown(`Large outbound volume (${megabytesSent.toFixed(1)} MB)`, 35);
        if (megabytesSent > 100) addBreakdown(`Extremely high volume`, 25);
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("Legitimate cloud backups or software updates can generate similar traffic.");
        summary = `Data exfiltration is suspected: an unusually large amount of outbound data was sent to external destinations in a short time window.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Potential DNS Tunneling') {
        const { queryCount, windowSeconds } = evidence;
        explanation.push(`The host made ${queryCount} suspicious DNS queries in the last ${windowSeconds} seconds.`);
        addBreakdown(`High query count (${queryCount})`, 30);
        if (queryCount > 200) addBreakdown(`Extremely high query rate`, 25);
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("Some applications generate many DNS queries legitimately.");
        summary = `The detection engine identified behaviour consistent with DNS tunneling: an unusually high number of suspicious DNS queries were observed.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Tor Connection') {
        explanation.push(`The host communicated with a known Tor exit node.`);
        addBreakdown(`Tor node detected`, 40);
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("Some users legitimately use Tor for privacy.");
        summary = `A connection to a Tor exit node was detected, which may indicate anonymisation activity.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Suspicious Geolocation') {
        const { countryCode, countryName, isHighRisk } = evidence;
        explanation.push(`The host connected to ${countryName} (${countryCode}), which is a high‑risk country.`);
        addBreakdown(`High‑risk country (${countryCode})`, 40);
        if (isHighRisk && countryCode === 'KP') addBreakdown(`Extreme risk (North Korea)`, 20);
        if (evidence.mitre) {
            explanation.push(`Behaviour matches MITRE ${evidence.mitre} (${MITRE_INFO[evidence.mitre] || ''}).`);
            addBreakdown(`MITRE correlation`, 10);
        }
        whyNot100.push("Some legitimate business partners may be in high‑risk regions.");
        summary = `The host communicated with a country classified as high‑risk, which may indicate geopolitical or threat‑actor activity.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Blacklist Hit') {
        explanation.push(`Traffic matched a known blacklist entry.`);
        addBreakdown(`Blacklist match`, 45);
        whyNot100.push("Blacklists can contain false positives.");
        summary = `The traffic matched an entry in the threat intelligence blacklist, indicating a known malicious IP or domain.`;
        evidenceCount = countIndicators();
    }
    else if (type === 'Signature Match') {
        const pattern = evidence.pattern || 'unknown';
        explanation.push(`The payload matched a signature pattern: "${pattern}".`);
        addBreakdown(`Signature match`, 35);
        whyNot100.push("Signatures can be too broad or outdated.");
        summary = `A signature-based detection triggered: the payload contained a known malicious pattern.`;
        evidenceCount = countIndicators();
    }
    else if (type.includes('IOC Match')) {
        const { iocType, iocValue } = evidence;
        explanation.push(`Traffic matched IOC ${iocValue} (${iocType}).`);
        addBreakdown(`IOC match (${iocType})`, 45);
        whyNot100.push("IOC may be outdated or a false positive.");
        summary = `The traffic matched an Indicator of Compromise, suggesting possible threat actor activity.`;
        evidenceCount = countIndicators();
    }

    
    else if (type.includes('Custom Rule Match')) {
        const { ruleName, conditions } = evidence;
        explanation.push(`Event matched custom rule "${ruleName}" with conditions: ${conditions}.`);
        addBreakdown(`Custom rule match`, 30);
        whyNot100.push("Custom rules can be overly broad.");
        summary = `A custom detection rule was triggered, indicating behaviour matching predefined criteria.`;
        evidenceCount = countIndicators();
    }

    
    else if (type === 'Host Risk Change') {
        const { oldStatus, newStatus, score } = evidence;
        explanation.push(`The host's risk status changed from ${oldStatus} to ${newStatus} (score: ${score.toFixed(1)}).`);
        addBreakdown(`Status change`, 25);
        whyNot100.push("Risk scores can fluctuate due to normal activity.");
        summary = `The host's risk level changed, reflecting updated threat assessment based on recent behaviour.`;
        evidenceCount = countIndicators();
    }

    
    else if (type.includes('Multi‑Stage')) {
        const { stages } = evidence;
        explanation.push(`The host exhibited a sequence of stages: ${stages.join(' → ')}.`);
        addBreakdown(`Full attack chain`, 40);
        whyNot100.push("The chain could be coincidental; further investigation required.");
        summary = `A multi‑stage attack chain was detected, indicating a progression from reconnaissance to potential compromise.`;
        evidenceCount = countIndicators();
    }

    
    else {
        explanation.push(`Alert triggered: ${alert.details}`);
        addBreakdown(`Generic detection`, 30);
        whyNot100.push("Limited contextual evidence available.");
        summary = `An alert was generated based on available security telemetry. Further investigation is recommended.`;
        evidenceCount = 1; 
    }

    
    let totalContribution = confidenceBreakdown.reduce((sum, item) => sum + item.contribution, 0);
    if (totalContribution === 0) totalContribution = 1;
    const scaleFactor = alert.confidence / totalContribution;
    confidenceBreakdown.forEach(item => {
        item.contribution = Math.round(item.contribution * scaleFactor);
    });
    let sum = confidenceBreakdown.reduce((s, i) => s + i.contribution, 0);
    if (sum !== alert.confidence && confidenceBreakdown.length > 0) {
        const diff = alert.confidence - sum;
        confidenceBreakdown[0].contribution += diff;
    }

    if (whyNot100.length === 0 && alert.confidence < 100) {
        whyNot100.push("The decision was based on statistical patterns, which are rarely perfect.");
    }

    const aiModel = "Behaviour Analysis Engine v2.0";

     const { summary: actionSummary, actions } = generateRecommendedActions(alert);

    if (!summary || summary === '') {
        summary = actionSummary;
    }



    return {
        summary,
        explanation,
        confidenceBreakdown,
        whyNot100,
        aiModel,
        evidenceCount,
        mitreCount: evidence.mitre ? 1 : 0,
        iocCount: (evidence.isIOC || evidence.iocType) ? 1 : 0,
        recommendedActions : actions
    };
}

function formatAlertTime(alert) {
    return new Date(alert.eventTimestamp).toLocaleTimeString();
}


const indices = {
    alertsByHost: new Map(),   
    packetsByHost: new Map(),  
    casesByAlert: new Map(),   
    iocsByAlert: new Map(),    
    actionsByAlert: new Map(), 
};

function rebuildIndices() {
    indices.alertsByHost.clear();
    indices.packetsByHost.clear();
    indices.casesByAlert.clear();
    indices.iocsByAlert.clear();
    indices.actionsByAlert.clear();

    timelineEvents.forEach(alert => {
        if (alert.src) {
            if (!indices.alertsByHost.has(alert.src)) indices.alertsByHost.set(alert.src, new Set());
            indices.alertsByHost.get(alert.src).add(alert.id);
        }
        if (alert.dst) {
            if (!indices.alertsByHost.has(alert.dst)) indices.alertsByHost.set(alert.dst, new Set());
            indices.alertsByHost.get(alert.dst).add(alert.id);
        }
    });

    
    globalPacketData.forEach(pkt => {
        if (pkt.src) {
            if (!indices.packetsByHost.has(pkt.src)) indices.packetsByHost.set(pkt.src, new Set());
            indices.packetsByHost.get(pkt.src).add(pkt.id);
        }
        if (pkt.dst) {
            if (!indices.packetsByHost.has(pkt.dst)) indices.packetsByHost.set(pkt.dst, new Set());
            indices.packetsByHost.get(pkt.dst).add(pkt.id);
        }
    });

    cases.forEach(c => {
        if (c.alerts) {
            c.alerts.forEach(alertId => {
                if (!indices.casesByAlert.has(alertId)) indices.casesByAlert.set(alertId, new Set());
                indices.casesByAlert.get(alertId).add(c.id);
            });
        }
    });

    iocs.forEach(ioc => {
        if (ioc.alertIds) {
            ioc.alertIds.forEach(alertId => {
                if (!indices.iocsByAlert.has(alertId)) indices.iocsByAlert.set(alertId, new Set());
                indices.iocsByAlert.get(alertId).add(ioc.id);
            });
        }
    });

    actionLogs.forEach(log => {
        if (log.alertId) {
            if (!indices.actionsByAlert.has(log.alertId)) indices.actionsByAlert.set(log.alertId, new Set());
            indices.actionsByAlert.get(log.alertId).add(log.id);
        }
    });
}

function computePriorityScore(alert) {
    const src = alert.src;
    let score = 0;
    const breakdown = [];

    
    const riskData = computeAIRiskScore(alert);
    const riskContrib = riskData.score * 0.45; 
    score += riskContrib;
    breakdown.push({ reason: 'AI Risk Score', contribution: Math.round(riskContrib) });

    
    let criticalityContrib = 0;
    const asset = getAssetByIdentifier(src);
    if (asset) {
        const criticalityWeights = {
            'Critical': 30,
            'High': 22,
            'Medium': 12,
            'Low': 5
        };
        criticalityContrib = criticalityWeights[asset.criticality] || 0;
        breakdown.push({ reason: `Business Criticality (${asset.criticality})`, contribution: criticalityContrib });
        score += criticalityContrib;
    } else {
        
        criticalityContrib = 5;
        breakdown.push({ reason: 'Business Criticality (Unknown)', contribution: criticalityContrib });
        score += criticalityContrib;
    }

    
    let stageContrib = 0;
    if (src && hostStages.has(src)) {
        const stages = hostStages.get(src).stages;
        const phaseSet = new Set();
        for (const [stage] of stages) {
            const phase = PHASE_MAP[stage];
            if (phase) phaseSet.add(phase);
        }
        const progress = (phaseSet.size / PHASE_ORDER.length) * 100;
        stageContrib = Math.min(progress * 0.15, 15);
        breakdown.push({ reason: `Attack Chain Progress (${Math.round(progress)}%)`, contribution: Math.round(stageContrib) });
        score += stageContrib;
    }

    
    let incidentContrib = 0;
    if (src) {
        
        const relatedAlerts = timelineEvents.filter(e => e.src === src || e.dst === src);
        const hasOpenInvestigation = relatedAlerts.some(e => e.status === 'investigating');
        const hasOpenCase = cases.some(c => {
            if (!c.alerts) return false;
            return c.alerts.some(alertId => relatedAlerts.some(e => e.id === alertId)) && c.status !== 'resolved';
        });
        if (hasOpenInvestigation) {
            incidentContrib += 7;
            breakdown.push({ reason: 'Host already under investigation', contribution: 7 });
        }
        if (hasOpenCase) {
            incidentContrib += 3;
            breakdown.push({ reason: 'Host has open case', contribution: 3 });
        }
        score += incidentContrib;
    }

    
    const age = Date.now() - (alert.eventTimestamp || Date.now());
    const freshnessBonus = Math.max(0, Math.min(5, 5 - age / 60000)); 
    if (freshnessBonus > 0) {
        breakdown.push({ reason: `Recent alert (${Math.round(age/1000)}s ago)`, contribution: Math.round(freshnessBonus) });
        score += freshnessBonus;
    }

    
    score = Math.min(score, 100);

    
    const totalContrib = breakdown.reduce((sum, item) => sum + item.contribution, 0);
    if (totalContrib > 0) {
        const scale = score / totalContrib;
        breakdown.forEach(item => {
            item.contribution = Math.round(item.contribution * scale);
        });
        
        let sum = breakdown.reduce((s, item) => s + item.contribution, 0);
        if (sum !== score && breakdown.length > 0) {
            const diff = score - sum;
            breakdown[0].contribution += diff;
        }
    } else {
        breakdown.push({ reason: 'Base detection', contribution: score });
    }

    
    let level = 'Low';
    let levelIcon = '⚪';
    let levelColor = '#6b7280';
    if (score >= 85) {
        level = 'Critical';
        levelIcon = '🔴';
        levelColor = '#ef4444';
    } else if (score >= 70) {
        level = 'High';
        levelIcon = '🟠';
        levelColor = '#f97316';
    } else if (score >= 50) {
        level = 'Medium';
        levelIcon = '🟡';
        levelColor = '#f59e0b';
    } else {
        levelIcon = '🟢';
        levelColor = '#10b981';
    }

    
    const topFactors = breakdown.slice().sort((a, b) => b.contribution - a.contribution).slice(0, 3);
    const reason = topFactors.map(f => `${f.reason} (${f.contribution})`).join(', ');

    return {
        score: Math.round(score),
        level,
        levelIcon,
        levelColor,
        breakdown,
        reason: `Priority ${level}: ${reason}`
    };
}

function renderPriorityQueue() {
    const tbody = document.getElementById('priority-tbody');
    if (!tbody) return;

    
    const openAlerts = timelineEvents.filter(e => e.status === 'open' || e.status === 'investigating');

    if (openAlerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No open alerts to prioritise.</td></tr>';
        return;
    }

    
    const withPriority = openAlerts.map(alert => ({
        alert,
        priority: computePriorityScore(alert)
    }));
    withPriority.sort((a, b) => b.priority.score - a.priority.score);

    tbody.innerHTML = '';
    withPriority.forEach(({ alert, priority }) => {
        const row = document.createElement('tr');
        const levelClass = priority.level === 'Critical' ? 'severity-critical' :
                           priority.level === 'High' ? 'severity-high' :
                           priority.level === 'Medium' ? 'severity-medium' : 'severity-low';

        
        const priorityDisplay = `
            <span style="display:flex; align-items:center; gap:4px;">
                <span style="font-size:18px;">${priority.levelIcon}</span>
                <strong style="color:${priority.levelColor};">${priority.score}</strong>
                <span class="${levelClass}" style="font-size:12px; padding:2px 8px;">${priority.level}</span>
            </span>
        `;

       
        let breakdownHtml = priority.breakdown.map(b => `${b.reason}: +${b.contribution}`).join('\n');
        const reasonTooltip = `
            <span class="priority-reason" style="cursor:help; border-bottom:1px dotted var(--text-muted); position:relative;">
                ${priority.reason.length > 60 ? priority.reason.slice(0,60)+'…' : priority.reason}
                <span class="priority-tooltip">
                    <strong>${priority.reason}</strong><br>
                    <span style="font-size:12px; color:var(--text-muted);">Breakdown:</span><br>
                    ${breakdownHtml}
                </span>
            </span>
        `;

        row.innerHTML = `
            <td>${formatAlertTime(alert)}</td>
            <td><span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
            <td>${alert.eventType}</td>
            <td>${alert.src || '—'} ${alert.dst ? `→ ${alert.dst}` : ''}</td>
            <td>${priorityDisplay}</td>
            <td>${reasonTooltip}</td>
            <td><button class="btn-action investigate" data-id="${alert.id}">Investigate</button></td>
        `;
        tbody.appendChild(row);
    });

    
    tbody.querySelectorAll('.investigate').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            openAlertInvestigation(id);
        });
    });

    
    document.getElementById('priority-total').textContent = withPriority.length;
    if (withPriority.length > 0) {
        const top = withPriority[0].priority;
        document.getElementById('priority-highest').textContent = `${top.score} (${top.level})`;
        document.getElementById('priority-highest-detail').textContent = withPriority[0].alert.eventType;
    } else {
        document.getElementById('priority-highest').textContent = '—';
        document.getElementById('priority-highest-detail').textContent = 'No alerts';
    }
}

function getAssetByIdentifier(identifier) {
    if (!identifier) return null;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(identifier)) {
        return assets.find(a => a.ip === identifier);
    }
    return assets.find(a => a.hostname === identifier || String(a.id) === identifier);
}

function shouldAlert(key, cooldownSeconds = 60) {
    const now = Date.now();
    const last = lastAlert.get(key);
    if (last && (now - last) < cooldownSeconds * 1000) return false;
    lastAlert.set(key, now);
    return true;
}

const RULE_FIELDS = [
    { value: 'src_ip', label: 'Source IP' },
    { value: 'dst_ip', label: 'Destination IP' },
    { value: 'protocol', label: 'Protocol' },
    { value: 'src_port', label: 'Source Port' },
    { value: 'dst_port', label: 'Destination Port' },
    { value: 'payload', label: 'Payload' },
    { value: 'country_src', label: 'Source Country' },
    { value: 'country_dst', label: 'Destination Country' },
    { value: 'packet_size', label: 'Packet Size' },      
    { value: 'entropy', label: 'Entropy' },             
    { value: 'frequency', label: 'Frequency' },         
    { value: 'risk_score', label: 'Risk Score' },        
];

const RULE_OPERATORS = [
    { value: 'eq', label: 'Equals' },
    { value: 'ne', label: 'Not Equals' },
    { value: 'contains', label: 'Contains' },
    { value: 'not_contains', label: 'Does Not Contain' },
    { value: 'gt', label: 'Greater Than' },
    { value: 'lt', label: 'Less Than' },
    { value: 'in', label: 'In (comma-separated)' },
    { value: 'not_in', label: 'Not In (comma-separated)' },
    { value: 'regex', label: 'Regex Match' },             
];

const MITRE_TECHNIQUES = {
    "T1046": { name: "Network Service Discovery", tactic: "Reconnaissance", url: "https://attack.mitre.org/techniques/T1046/" },
    "T1595": { name: "Active Scanning", tactic: "Reconnaissance", url: "https://attack.mitre.org/techniques/T1595/" },
    "T1110": { name: "Brute Force", tactic: "Credential Access", url: "https://attack.mitre.org/techniques/T1110/" },
    "T1071": { name: "Application Layer Protocol", tactic: "Command & Control", url: "https://attack.mitre.org/techniques/T1071/" },
    "T1071.004": { name: "DNS Tunneling", tactic: "Command & Control", url: "https://attack.mitre.org/techniques/T1071.004/" },
    "T1090": { name: "Proxy", tactic: "Command & Control", url: "https://attack.mitre.org/techniques/T1090/" },
    "T1041": { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", url: "https://attack.mitre.org/techniques/T1041/" },
    "T1190": { name: "Exploit Public-Facing Application", tactic: "Initial Access", url: "https://attack.mitre.org/techniques/T1190/" },
    
};


const TACTIC_TECHNIQUES = {};
Object.keys(MITRE_TECHNIQUES).forEach(tech => {
    const tactic = MITRE_TECHNIQUES[tech].tactic;
    if (!TACTIC_TECHNIQUES[tactic]) TACTIC_TECHNIQUES[tactic] = [];
    TACTIC_TECHNIQUES[tactic].push(tech);
});
const TACTIC_ORDER = ['Reconnaissance', 'Initial Access', 'Credential Access', 'Command & Control', 'Exfiltration']; 


function generateCaseId() {
    return nextCaseId++;
}

loadCases();
loadIOCs();
loadResponsePolicies();
loadRules();
updateTopIOCWidget();

const MAX_PACKET_HISTORY = 5000;
let sankeyInitialized = false;

let lastDetectionTime = 0;

const actionMenu = document.getElementById("packet-action-menu");
const editBtn = document.getElementById("packet-edit-btn");
const deleteBtn = document.getElementById("packet-delete-btn");
const mlInfoMap = new Map(); 


const STAGE_MAP = {
    'Horizontal Port Scan': 'scan',
    'Vertical Port Scan': 'scan',
    'Brute Force Attempt': 'access',
    'Possible Data Exfiltration': 'exfil',
    'Data Exfiltration': 'exfil',
    'Potential C2 Activity': 'c2',
    'Beaconing to Malicious Host': 'c2',
    'Beaconing': 'c2',
    'DNS Tunneling': 'dns_tunnel',
    'Tor Connection': 'tor',
    'Suspicious Geolocation': 'geo'
};


const MITRE_MAP = {
    'Horizontal Port Scan': 'T1046',
    'Vertical Port Scan': 'T1046',
    'Brute Force Attempt': 'T1110',
    'Potential C2': 'T1071',
    'Beaconing': 'T1071',
    'Beaconing to Malicious Host': 'T1071',
    'DNS Tunneling': 'T1071.004',
    'Data Exfiltration': 'T1041',
    'Possible Data Exfiltration': 'T1041',
    'Tor Connection': 'T1090',
    'Multi-Stage Attack Chain': 'T1190',
    'Suspicious Activity Pattern': 'T1595'
};

const MITRE_INFO = {
    'T1046': 'Network Service Discovery',
    'T1110': 'Brute Force',
    'T1071': 'Application Layer Protocol',
    'T1071.004': 'DNS Tunneling',
    'T1041': 'Exfiltration Over C2 Channel',
    'T1090': 'Proxy',
    'T1190': 'Exploit Public-Facing Application',
    'T1595': 'Active Scanning'
};


let BRUTE_FORCE_THRESHOLD = 20;
let BRUTE_FORCE_COOLDOWN = 300;
let BRUTE_FORCE_WINDOW = 60000;

let BEACON_MAX_VARIANCE_RATIO = 0.35;
let BEACON_MIN_DURATION = 60000;
let BEACON_MIN_CONNECTIONS = 4;
let BEACON_COOLDOWN = 600;

let EXFIL_OUTBOUND_THRESHOLD_BYTES = 50 * 1024 * 1024;
let EXFIL_WINDOW_MS = 10 * 60 * 1000;
let EXFIL_COOLDOWN = 600;

let PORT_SCAN_THRESHOLD = 15;      
let PORT_SCAN_HORIZONTAL_TARGETS = 10;
let PORT_SCAN_COOLDOWN = 120;

let DNS_TUNNELING_THRESHOLD = 100;
let DNS_TUNNELING_WINDOW = 60000;
let DNS_TUNNELING_COOLDOWN = 300;

let C2_MAX_VARIANCE_RATIO = 0.35;
let C2_MIN_DURATION = 60000;
let C2_MIN_CONNECTIONS = 3;
let C2_COOLDOWN = 600;

const DETECTION_PROFILES = {
    balanced: {
        label: 'Balanced',
        thresholds: {
            BRUTE_FORCE_THRESHOLD: 20,
            BEACON_MAX_VARIANCE_RATIO: 0.35,
            BEACON_MIN_DURATION: 60000,
            BEACON_MIN_CONNECTIONS: 4,
            EXFIL_OUTBOUND_THRESHOLD_BYTES: 50 * 1024 * 1024,
            PORT_SCAN_THRESHOLD: 15,
            PORT_SCAN_HORIZONTAL_TARGETS: 10,
            DNS_TUNNELING_THRESHOLD: 100,
            C2_MAX_VARIANCE_RATIO: 0.35,
            C2_MIN_DURATION: 60000,
        }
    },
    strict: {
        label: 'Strict',
        thresholds: {
            BRUTE_FORCE_THRESHOLD: 15,          
            BEACON_MAX_VARIANCE_RATIO: 0.25,     
            BEACON_MIN_DURATION: 90000,         
            BEACON_MIN_CONNECTIONS: 5,
            EXFIL_OUTBOUND_THRESHOLD_BYTES: 30 * 1024 * 1024, 
            PORT_SCAN_THRESHOLD: 12,              
            PORT_SCAN_HORIZONTAL_TARGETS: 8,
            DNS_TUNNELING_THRESHOLD: 75,
            C2_MAX_VARIANCE_RATIO: 0.25,
            C2_MIN_DURATION: 90000,
        }
    },
    paranoid: {
        label: 'Paranoid',
        thresholds: {
            BRUTE_FORCE_THRESHOLD: 5,             
            BEACON_MAX_VARIANCE_RATIO: 0.5,       
            BEACON_MIN_DURATION: 30000,           
            BEACON_MIN_CONNECTIONS: 3,
            EXFIL_OUTBOUND_THRESHOLD_BYTES: 10 * 1024 * 1024,
            PORT_SCAN_THRESHOLD: 8,
            PORT_SCAN_HORIZONTAL_TARGETS: 5,
            DNS_TUNNELING_THRESHOLD: 30,
            C2_MAX_VARIANCE_RATIO: 0.5,
            C2_MIN_DURATION: 30000,
        }
    }
};

let currentProfile = 'balanced';

function applyProfile(profileName) {
    const profile = DETECTION_PROFILES[profileName];
    if (!profile) return;

    const oldProfile = currentProfile;
    currentProfile = profileName;
    const t = profile.thresholds;

    if (t.BRUTE_FORCE_THRESHOLD !== undefined) BRUTE_FORCE_THRESHOLD = t.BRUTE_FORCE_THRESHOLD;
    if (t.BEACON_MAX_VARIANCE_RATIO !== undefined) BEACON_MAX_VARIANCE_RATIO = t.BEACON_MAX_VARIANCE_RATIO;
    if (t.BEACON_MIN_DURATION !== undefined) BEACON_MIN_DURATION = t.BEACON_MIN_DURATION;
    if (t.BEACON_MIN_CONNECTIONS !== undefined) BEACON_MIN_CONNECTIONS = t.BEACON_MIN_CONNECTIONS;
    if (t.EXFIL_OUTBOUND_THRESHOLD_BYTES !== undefined) EXFIL_OUTBOUND_THRESHOLD_BYTES = t.EXFIL_OUTBOUND_THRESHOLD_BYTES;
    if (t.PORT_SCAN_THRESHOLD !== undefined) PORT_SCAN_THRESHOLD = t.PORT_SCAN_THRESHOLD;
    if (t.PORT_SCAN_HORIZONTAL_TARGETS !== undefined) PORT_SCAN_HORIZONTAL_TARGETS = t.PORT_SCAN_HORIZONTAL_TARGETS;
    if (t.DNS_TUNNELING_THRESHOLD !== undefined) DNS_TUNNELING_THRESHOLD = t.DNS_TUNNELING_THRESHOLD;
    if (t.C2_MAX_VARIANCE_RATIO !== undefined) C2_MAX_VARIANCE_RATIO = t.C2_MAX_VARIANCE_RATIO;
    if (t.C2_MIN_DURATION !== undefined) C2_MIN_DURATION = t.C2_MIN_DURATION;

    const labelEl = document.getElementById('detection-mode-label');
    if (labelEl) {
        labelEl.textContent = profile.label;
    }
    const selectEl = document.getElementById('detection-mode-select');
    if (selectEl) {
        selectEl.value = profileName;
    }

    try {
        localStorage.setItem('detectionProfile', profileName);
    } catch (e) {}

    const changeMsg = oldProfile && oldProfile !== profileName
        ? `Detection mode changed from ${DETECTION_PROFILES[oldProfile]?.label || oldProfile} to ${profile.label}`
        : `Detection mode set to ${profile.label}`;
    addTimelineEvent('Detection Profile Changed', 'low', changeMsg, 'System');

    showToast(`Detection mode switched to ${profile.label}`, 'success');
}

(function loadSavedProfile() {
    try {
        const saved = localStorage.getItem('detectionProfile');
        if (saved && DETECTION_PROFILES[saved]) {
            applyProfile(saved);
            const select = document.getElementById('detection-mode-select');
            if (select) select.value = saved;
        } else {
            applyProfile('balanced');
        }
    } catch (e) {
        applyProfile('balanced');
    }
})();

document.getElementById('detection-mode-select')?.addEventListener('change', function(e) {
    applyProfile(e.target.value);
});

renderPackets = function(data) {
  console.log("🔄 renderPackets called with", data.length, "packets");
  
  const table = document.getElementById('packet-table');
  if (!table) return;
  
  let tbody = table.querySelector('tbody');
  if (!tbody) {
    tbody = document.createElement('tbody');
    table.appendChild(tbody);
  }
  
  tbody.innerHTML = '';
  
  const packetCount = document.getElementById('packets-captured');
  if (packetCount) packetCount.textContent = data.length;
  
  data.slice().reverse().forEach(packet => {
    const row = tbody.insertRow();
    const fullPayload = packet.payload ? sanitize(packet.payload) : '';
    const shortPayload = fullPayload.length > 30 ? fullPayload.slice(0, 30) + '...' : fullPayload;

    row.innerHTML = `
        <td>${packet.time}</td>
        <td><span class="ip-intel-trigger" data-ip="${packet.src}">${packet.src}</span></td>
        <td>${packet.src_port || 'Unknown'}</td>
        <td><span class="ip-intel-trigger" data-ip="${packet.dst}">${packet.dst}</span></td>
        <td>${packet.dst_port || 'Unknown'}</td>
        <td>${packet.proto}</td>
        <td title="${fullPayload}">${shortPayload || 'n/a'}</td>
        <td class="action-cell"><button class="row-action-btn" data-id="${packet.id}"><i class="fas fa-ellipsis-v"></i></button></td>
    `;
    
    row.addEventListener('click', (e) => {
      if (e.target.closest('.row-action-btn')) {
        e.stopPropagation();
        selectedPacketId = packet.id;
        showPacketActionMenu(e.target.closest('.row-action-btn'));
      } else {
        openDrawer(packet);
      }
    });
  });
  
  table.style.display = 'none';
  table.offsetHeight;
  table.style.display = '';
};

renderPackets(applyFilters(globalPacketData));
function showPacketActionMenu(rowElement) {
  const rect = rowElement.getBoundingClientRect();
  actionMenu.style.top = `${rect.top + window.scrollY - actionMenu.offsetHeight - 5}px`;
  actionMenu.style.left = `${rect.left + window.scrollX + rect.width / 2 - 50}px`;
  actionMenu.classList.remove("hidden");
}

editBtn.addEventListener("click", () => {
  if (!selectedPacketId) {
    console.warn("⚠️ No packet selected for editing");
    return;
  }

  openManipulateModalById(selectedPacketId);
  actionMenu.classList.add("hidden");
});

deleteBtn.addEventListener("click", () => {
  if (selectedPacketId) {
    globalPacketData = globalPacketData.filter(pkt => pkt.id !== selectedPacketId);
    renderPackets(applyFilters(globalPacketData));
    updateFlowAnalysisTable();        
    if (geoViewVisible) {
        updateGeoStats();             
    }
    showToast("Packet deleted successfully.", "danger");
    actionMenu.classList.add("hidden");
  }
});

document.addEventListener("click", () => {
  actionMenu.classList.add("hidden");
});

function sanitize(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function fetchPackets() {
  fetch('/api/packets')
    .then(response => response.json())
    .then(data => {
      let limitedData = data.slice(-MAX_PACKET_HISTORY);
      globalPacketData = limitedData
        .filter(pkt => !blockedIPs.has(pkt.src) && !blockedIPs.has(pkt.dst))
        .map((pkt, index) => {
          if (!pkt.id) {
            pkt.id = `${Date.now()}-${index}-${Math.random().toString(36).slice(2, 7)}`;
          }
          if (!pkt.timestamp) {
            if (pkt.time) {
              const today = new Date();
              const parts = pkt.time.split(':');
              if (parts.length === 3) {
                today.setHours(parseInt(parts[0]), parseInt(parts[1]), parseInt(parts[2]), 0);
                pkt.timestamp = today.getTime();
              } else {
                pkt.timestamp = Date.now();
              }
            } else {
              pkt.timestamp = Date.now();
            }
          }
          return pkt;
        });

      console.log("🧠 Packets after fetch:", globalPacketData.length, "packets");

      const pingCount = globalPacketData.filter(p => p.dst === "8.8.8.8" || p.src === "8.8.8.8").length;
      console.log(`📊 Ping packets in store: ${pingCount}`);

      window._portFreq = new Map();
          globalPacketData.forEach(p => {
              if (p.dst_port) window._portFreq.set(p.dst_port, (window._portFreq.get(p.dst_port) || 0) + 1);
              if (p.src_port) window._portFreq.set(p.src_port, (window._portFreq.get(p.src_port) || 0) + 1);
      });

      renderPackets(applyFilters(globalPacketData));
      if (geoViewVisible) {
        updateGeoStats();
      }
      updateFlowAnalysisTable();
      const packetsCapturedElem = document.getElementById('packets-captured');
      if (packetsCapturedElem) packetsCapturedElem.textContent = globalPacketData.length;
      rebuildIndices()
    })
    .catch(error => console.error('Error fetching packets:', error));
}

document.getElementById('protocolFilter').addEventListener('input', fetchPackets);
document.getElementById('srcFilter').addEventListener('input', fetchPackets);
document.getElementById('dstFilter').addEventListener('input', fetchPackets);
document.getElementById('srcPortFilter').addEventListener('input', fetchPackets);
document.getElementById('dstPortFilter').addEventListener('input', fetchPackets);
document.getElementById('payloadFilter').addEventListener('input', fetchPackets);

['exactTime', 'startTime', 'endTime'].forEach(id => {
  document.getElementById(id).addEventListener('input', () => {
    const filtered = applyFilters(globalPacketData);
    renderPackets(filtered);
  });
});

const playBtn = document.getElementById('play-btn');
const pauseBtn = document.getElementById('pause-btn');
const stopBtn = document.getElementById('stop-btn');
const restartBtn = document.getElementById('restart-btn');

function clearControlStates() {
  playBtn.classList.remove('active-play');
  pauseBtn.classList.remove('active-pause');
  stopBtn.classList.remove('active-stop');
}

function updatePacketCount() {
  fetch('/api/packet_count')
    .then(response => response.json())
    .then(data => {
      document.getElementById('total-captured').textContent = data.total;
    })
    .catch(error => console.error('Error fetching packet count:', error));
}

let timeLabels = [];
let packetCounts = [];
let protocolCounts = { TCP: 0, UDP: 0, ICMP: 0 };
let protocolHistory = {};
let dynamicProtocolCounts = {};

const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Protocol Count',
      data: [],
      backgroundColor: [],
    }]
  },
  options: {
    scales: {
      x: { ticks: { color: '#ccc' } },
      y: { ticks: { color: '#ccc' }, beginAtZero: true }
    },
    plugins: {
      legend: { labels: { color: '#ccc' } }
    }
  }
});

const protocolOverTimeCtx = document.getElementById('protocolOverTimeChart').getContext('2d');
const protocolOverTimeChart = new Chart(protocolOverTimeCtx, {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: []
  },
  options: {
    scales: {
      x: { ticks: { color: '#ccc' } },
      y: { ticks: { color: '#ccc' }, beginAtZero: true }
    },
    plugins: {
      legend: { labels: { color: '#ccc' } }
    }
  }
});

const commonPortsCtx = document.getElementById('commonPortsChart').getContext('2d');
const commonPortsChart = new Chart(commonPortsCtx, {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Most Common Ports',
      data: [],
      backgroundColor: '#8e44ad'
    }]
  },
  options: {
    scales: {
      x: {
        ticks: { color: '#ccc' },
        title: { display: true, text: 'Port', color: '#ccc' }
      },
      y: {
        ticks: { color: '#ccc' },
        title: { display: true, text: 'Count', color: '#ccc' },
        beginAtZero: true
      }
    },
    plugins: {
      legend: { labels: { color: '#ccc' } }
    }
  }
});

function initGeoSpecificCharts() {
    const ctxThreat = document.getElementById('geoThreatChart').getContext('2d');
    geoThreatChart = new Chart(ctxThreat, {
        type: 'pie',
        data: { labels: ['Critical (80+)', 'High (50-79)', 'Medium (25-49)', 'Low (0-24)'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#10b981'] }] },
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom', labels: { color: '#ccc' } } } }
    });
    const ctxBar = document.getElementById('geoSourceBarChart').getContext('2d');
    geoSourceBarChart = new Chart(ctxBar, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: '#6366f1' }] },
        options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true, ticks: { color: '#ccc' } }, x: { ticks: { color: '#ccc', maxRotation: 45, minRotation: 45 } } } }
    });
    const ctxTimeline = document.getElementById('geoRiskTimeline').getContext('2d');
    geoRiskTimeline = new Chart(ctxTimeline, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Average Risk', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', tension: 0.3, fill: true }] },
        options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true, max: 100, ticks: { color: '#ccc' } }, x: { ticks: { color: '#ccc' } } } }
    });
}

let detectionCounts = {
    portScan: 0,
    bruteForce: 0,
    blacklist: 0,
    signature: 0,
    beaconing: 0,
    dnsTunneling: 0,
    exfiltration: 0,
    hostRisk: 0,
    torConnection: 0,
    c2Detection: 0,
};

function updateDetectionStatsDisplay() {
    document.getElementById('stat-portscan').textContent = detectionCounts.portScan;
    document.getElementById('stat-bruteforce').textContent = detectionCounts.bruteForce;
    document.getElementById('stat-blacklist').textContent = detectionCounts.blacklist;
    document.getElementById('stat-signature').textContent = detectionCounts.signature;
    document.getElementById('stat-beaconing').textContent = detectionCounts.beaconing;
    document.getElementById('stat-dnstunnel').textContent = detectionCounts.dnsTunneling;
    document.getElementById('stat-exfil').textContent = detectionCounts.exfiltration;
    document.getElementById('stat-hostrisk').textContent = detectionCounts.hostRisk;
    document.getElementById('stat-tor').textContent = detectionCounts.torConnection;
    document.getElementById('stat-c2').textContent = detectionCounts.c2Detection;
}

function incrementStat(category) {
    if (detectionCounts.hasOwnProperty(category)) {
        detectionCounts[category]++;
        updateDetectionStatsDisplay();
    }
}

function initAnalyticsCharts() {
  const ctxProto = document.getElementById('analyticsProtocolChart').getContext('2d');
  const ctxTraffic = document.getElementById('analyticsTrafficChart').getContext('2d');
  const ctxPorts = document.getElementById('analyticsPortsChart').getContext('2d');
  const ctxRisk = document.getElementById('analyticsRiskChart').getContext('2d');

  analyticsProtocolChart = new Chart(ctxProto, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Protocol Count', data: [], backgroundColor: [] }] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  });

  analyticsTrafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: { labels: [], datasets: [] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  });

  analyticsPortsChart = new Chart(ctxPorts, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Most Common Ports', data: [], backgroundColor: '#8e44ad' }] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  });

  analyticsRiskChart = new Chart(ctxRisk, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Risk Score', data: [], backgroundColor: [] }] },
    options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } }
  });
}

document.getElementById('export-charts-btn').addEventListener('click', () => {
  const chart1 = document.getElementById('protocolChart');
  const chart2 = document.getElementById('protocolOverTimeChart');
  const chart3 = document.getElementById('commonPortsChart');

  const width = Math.max(chart1.width, chart2.width, chart3.width);
  const height = chart1.height + chart2.height + chart3.height;

  const combinedCanvas = document.createElement('canvas');
  combinedCanvas.width = width;
  combinedCanvas.height = height;

  const ctx = combinedCanvas.getContext('2d');
  ctx.drawImage(chart1, 0, 0);
  ctx.drawImage(chart2, 0, chart1.height);
  ctx.drawImage(chart3, 0, chart1.height + chart2.height);
  const link = document.createElement('a');
  link.download = 'combined_charts.png';
  link.href = combinedCanvas.toDataURL('image/png');
  link.click();
});

let monitoring = true;
let intervalId = null;

pauseBtn.addEventListener('click', () => {
  clearControlStates();
  pauseBtn.classList.add('active-pause');
  clearInterval(intervalId);
  intervalId = null;
  monitoring = false;
  fetch('/api/pause_monitoring', { method: 'POST' });
});

playBtn.addEventListener('click', () => {
  clearControlStates();
  playBtn.classList.add('active-play');
  if (!intervalId) {
    fetch('/api/start_monitoring', { method: 'POST' })
      .then(() => {
        intervalId = setInterval(updateChartsAndPackets, 2000);
        monitoring = true;
      });
  }
});

stopBtn.addEventListener('click', () => {
  clearControlStates();
  lastDetectionTime = 0;
  stopBtn.classList.add('active-stop');
  clearInterval(intervalId);
  intervalId = null;
  monitoring = false;

  timeLabels.length = 0;
  packetCounts.length = 0;
  protocolHistory = {};
  protocolChart.data.labels = [];
  protocolChart.data.datasets[0].data = [];
  protocolOverTimeChart.data.datasets = [];
  protocolChart.update();
  protocolOverTimeChart.update();
});

restartBtn.addEventListener('click', () => {
  clearInterval(intervalId);
  lastDetectionTime = 0;
  intervalId = null;

  timeLabels.length = 0;
  packetCounts.length = 0;
  protocolHistory = {};
  protocolChart.data.labels = [];
  protocolChart.data.datasets[0].data = [];
  protocolOverTimeChart.data.datasets = [];
  document.getElementById('packet-table').innerHTML = '';
  document.getElementById('protocolFilter').value = '';
  document.getElementById('srcFilter').value = '';
  document.getElementById('dstFilter').value = '';
  protocolChart.update();
  protocolOverTimeChart.update();

  fetch('/api/reset', { method: 'POST' })
    .then(() => {
      return fetch('/api/start_monitoring', { method: 'POST' });
    })
    .then(() => {
      updatePacketCount();
      intervalId = setInterval(updateChartsAndPackets, 2000);
    })
    .catch(err => console.error('Error during restart process:', err));
}); 

function switchView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById(`${viewId}-view`);
    if (target) target.classList.remove('hidden');
    document.querySelectorAll('.nav-item').forEach(nav => {
        nav.classList.remove('active');
        if (nav.dataset.view === viewId) nav.classList.add('active');
    });
    closeDrawer();

    if (viewId === 'alerts') {
        renderAlertsTable();
    }

    if (viewId === 'cases') {
    renderCasesTable();
    }

    if (viewId === 'ioc') {
    renderIOCs();

    }

    if(viewId === 'rules') {
    renderRulesTable();
    }

    if(viewId === 'assets'){
      renderAssetsTable();
    }

    if(viewId === 'mitre') {
      renderMitreCoverage();
    }

    if(viewId === 'assets') {
      renderAssetsTable();
    }

    if (viewId === 'automation') {
        renderPoliciesTable();
        renderActionLogs();
        updateActionStats();
        renderApprovalQueue();
        renderTemplates();
    }

    if (viewId === 'priority') {
        renderPriorityQueue();
    }

    if (viewId === 'investigation') {
    renderInvestigationGraph();
    setupGraphFilters();
    setTimeout(() => {
        if (investigationNetwork) {
            investigationNetwork.redraw();
            investigationNetwork.fit({ animation: true });
        }
    }, 150);
    }

    if(viewId === 'hunting') {
      loadSavedQueries();
    }

    if(viewId === 'ueba') {
      updateUEBA();
      renderUEBATable();
    }

    geoViewVisible = (viewId === 'geo');
    if (geoViewVisible) {
        updateGeoStats();
        setTimeout(() => window.geoMap?.invalidateSize(), 200);
    }
}
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    switchView(item.dataset.view);
    if (window.innerWidth <= 768) {
      document.getElementById('sidebar')?.classList.remove('open');
    }
  });
});


const hamburger = document.getElementById('hamburger');
const sidebar = document.getElementById('sidebar');
if (hamburger) {
  hamburger.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768 && sidebar.classList.contains('open') &&
        !sidebar.contains(e.target) && !hamburger.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

const drawer = document.getElementById('packet-drawer');
const drawerContent = document.getElementById('packet-drawer-content');
function openDrawer(packet) {
  currentDrawerPacket = packet;
  if (!packet) return;
  let html = `<strong>Time:</strong> ${packet.time}<br>`;
  html += `<strong>Source:</strong> ${packet.src}:${packet.src_port}<br>`;
  html += `<strong>Destination:</strong> ${packet.dst}:${packet.dst_port}<br>`;
  html += `<strong>Protocol:</strong> ${packet.proto}<br>`;
  html += `<strong>ML Label:</strong> ${packet.ml_label}<br>`;
  html += `<strong>Risk Score:</strong> ${packet.host_score}<br>`;
  html += `<strong>Payload:</strong><br><pre>${packet.payload || '(no payload)'}</pre>`;
   html += `<button class="btn-secondary" onclick="showRawPacketView(${JSON.stringify(packet).replace(/"/g, '&quot;')})" style="margin-top: 12px;"><i class="fas fa-code"></i> View Raw</button>`;
  drawerContent.innerHTML = html;
  drawer.classList.add('open');
}
function closeDrawer() {
  drawer?.classList.remove('open');
}
document.querySelector('.close-drawer')?.addEventListener('click', closeDrawer);

const globalSearchInput = document.getElementById('global-search');
function globalSearchFilter(packet) {
  if (!globalSearchInput || !globalSearchInput.value) return true;
  const term = globalSearchInput.value.toLowerCase();
  return (
    (packet.src && packet.src.toLowerCase().includes(term)) ||
    (packet.dst && packet.dst.toLowerCase().includes(term)) ||
    (packet.proto && packet.proto.toLowerCase().includes(term)) ||
    (packet.src_port && String(packet.src_port).includes(term)) ||
    (packet.dst_port && String(packet.dst_port).includes(term)) ||
    (packet.payload && packet.payload.toLowerCase().includes(term))
  );
}

const originalApplyFilters = applyFilters;
applyFilters = function(data) {
  let filtered = originalApplyFilters(data);
  if (globalSearchInput && globalSearchInput.value) {
    filtered = filtered.filter(globalSearchFilter);
  }
  return filtered;
};
globalSearchInput?.addEventListener('input', () => {
  renderPackets(applyFilters(globalPacketData));
});
function updateSystemHealth() {
  const now = Date.now();
  const elapsed = (now - lastPacketTime) / 1000;
  let pktPerSec = 0;
  if (elapsed > 0) {
    const diff = globalPacketData.length - lastPacketCount;
    pktPerSec = Math.round(diff / elapsed);
  }
  document.getElementById('packets-per-sec').textContent = pktPerSec;
  lastPacketCount = globalPacketData.length;
  lastPacketTime = now;
  document.getElementById('cpu-usage').textContent = Math.floor(Math.random() * 30 + 10) + '%';
  document.getElementById('mem-usage').textContent = Math.floor(Math.random() * 40 + 20) + '%';
}
setInterval(updateSystemHealth, 2000);

function getSeverity(riskScore) {
  if (riskScore >= 80) return 'critical';
  if (riskScore >= 50) return 'high';
  if (riskScore >= 25) return 'medium';
  return 'low';
}

function addTimelineEvent(eventType, severity, details, src = null, dst = null, extra = {}, confidence = 50, source = 'heuristic', explanation = null, evidence = null) {
    const now = Date.now();
    const event = {
        id: `evt-${now}-${Math.random().toString(36).slice(2, 6)}`,
        eventTimestamp: now,
        severity: severity,
        eventType: eventType,
        details: details,
        src: src,
        dst: dst,
        confidence: Math.min(100, Math.max(0, confidence)),
        status: "open", 
        assignedTo: null,
        notes: [],
        resolvedAt: null,
        falsePositiveReason: null,
        source: source,
        investigationNotes: [],
        acknowledgedAt: null,
        investigatedAt: null,
        explanation: explanation,
        evidence: evidence || null,
        incidentId: null,
        ...extra
    };

    if (MITRE_MAP[eventType]) {
        event.mitre = MITRE_MAP[eventType];
    }

    timelineEvents.unshift(event);
    if (timelineEvents.length > 200) timelineEvents.pop();

    if (event.status === 'open' && !event._automated) handleAutomatedResponse(event);

    if (src) {
        const stage = STAGE_MAP[eventType] || eventType;
        if (!hostStages.has(src)) {
            hostStages.set(src, { lastUpdated: Date.now(), stages: new Map() });
        }
        const entry = hostStages.get(src);
        entry.lastUpdated = Date.now();
        entry.stages.set(stage, Date.now());
    }
    renderTimeline();
    rebuildIndices();
    return event;

}function renderTimeline() {
    const tbody = document.querySelector('#timeline-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    timelineEvents.slice(0, 100).forEach(ev => {
        const row = document.createElement('tr');

        let mitreBadge = '';
        if (ev.mitre) {
            const name = MITRE_INFO[ev.mitre] || 'MITRE Technique';
            mitreBadge = `
                <a class="mitre-badge"
                   href="https://attack.mitre.org/techniques/${ev.mitre}/"
                   target="_blank"
                   title="${name} (${ev.mitre})">
                   ${ev.mitre}
                </a>
            `;
        }
        const confidenceBar = ev.confidence !== undefined ? `
            <div class="confidence-bar" title="${ev.confidence}% confidence">
                <div class="confidence-fill" style="width: ${ev.confidence}%; background: ${confidenceColor(ev.confidence)};"></div>
                <span class="confidence-label">${Math.round(ev.confidence)}%</span>
            </div>
        ` : '—';
          const mlInfo = mlInfoMap.get(ev.src);
          let mlBadge = '';
          if (mlInfo) {
              const label = mlInfo.label;
              const color = label === 'MALICIOUS' ? '#ef4444' :
                            label === 'BENIGN' ? '#10b981' :
                            label === 'UNCERTAIN' ? '#f59e0b' : '#6b7280';
              mlBadge = `<span class="ml-badge" style="background:${color};color:white;padding:2px 6px;border-radius:10px;font-size:10px;margin-left:6px;">${label}</span>`;
          }
          row.innerHTML = `
              <td>${formatAlertTime(ev)}</td>
              <td><span class="severity-${ev.severity}">${ev.severity.toUpperCase()}</span></td>
              <td>${ev.eventType} ${mlBadge}</td>
              <td>${ev.details}${ev.src ? ` (${ev.src} → ${ev.dst})` : ''} ${mitreBadge}</td>
              <td>${confidenceBar}</td>
                  `;

        row.addEventListener('click', function(e) {
            if (e.target.closest('a, button')) return;
            openAlertInvestigation(ev.id);
        });
        tbody.appendChild(row);
    });
    updateAlertMetrics();
}

document.getElementById('export-timeline')?.addEventListener('click', () => {
  const csv = ['Time,Severity,Event Type,Details'];
  timelineEvents.forEach(ev => {
    csv.push(`"${formatAlertTime(ev)}","${ev.severity}","${ev.eventType}","${ev.details.replace(/"/g, '""')}"`);
  });
  const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'attack_timeline.csv';
  link.click();
});

const PHASE_MAP = {
    'scan': 'Reconnaissance',
    'geo': 'Reconnaissance',
    'access': 'Initial Access',
    'c2': 'Command & Control',
    'dns_tunnel': 'Command & Control',
    'tor': 'Command & Control',
    'exfil': 'Exfiltration'
};

const PHASE_ICONS = {
    'Reconnaissance': '🔍',
    'Initial Access': '🔑',
    'Command & Control': '📡',
    'Exfiltration': '💾'
};

const PHASE_ORDER = ['Reconnaissance', 'Initial Access', 'Command & Control', 'Exfiltration'];
function renderKillChain(host) {
    if (!hostStages.has(host)) {
        return '<p>No activity recorded for this host.</p>';
    }
    const entry = hostStages.get(host);
    const stages = entry.stages; 

    
    const phaseTimestamps = new Map();
    for (const [stage, timestamp] of stages.entries()) {
        const phase = PHASE_MAP[stage];
        if (phase) {
            if (!phaseTimestamps.has(phase) || timestamp < phaseTimestamps.get(phase)) {
                phaseTimestamps.set(phase, timestamp);
            }
        }
    }

    const completedPhases = new Set(phaseTimestamps.keys());
    const progress = (completedPhases.size / PHASE_ORDER.length) * 100;

    
    let breakdownHtml = '';
    if (stages.size > 0) {
        let totalContrib = 0;
        const contribItems = [];
        for (const [stage, timestamp] of stages.entries()) {
            const points = STAGE_CONTRIBUTION[stage] || 0;
            if (points > 0) {
                totalContrib += points;
                contribItems.push(`<span class="contrib-item">${stage} +${points}</span>`);
            }
        }
        
        breakdownHtml = `
            <div class="killchain-breakdown">
                <h4>Score Contributors</h4>
                <div class="contrib-list">
                    ${contribItems.join(', ')}
                </div>
                <div class="contrib-total">Estimated total: <strong>${totalContrib}</strong></div>
                <div style="font-size:12px; color:var(--text-muted);">(Actual host score may vary due to decay)</div>
            </div>
        `;
    }

    
    let html = `<div class="killchain-progress">Progress: ${completedPhases.size}/${PHASE_ORDER.length} phases (${Math.round(progress)}%)</div>`;
    html += `<div class="killchain-container">`;

    PHASE_ORDER.forEach((phase, index) => {
        const completed = completedPhases.has(phase);
        const icon = PHASE_ICONS[phase] || '📌';
        const timestamp = phaseTimestamps.get(phase);
        const timeStr = timestamp ? new Date(timestamp).toLocaleTimeString() : '—';

        html += `
            <div class="phase-item ${completed ? 'completed' : ''}">
                <div class="phase-icon">${icon}</div>
                <div class="phase-name">${phase}</div>
                <div class="phase-status">${completed ? '✅ Completed' : '⏳ Pending'}</div>
                <div class="phase-time">${timeStr}</div>
            </div>
        `;
        if (index < PHASE_ORDER.length - 1) {
            html += `<div class="phase-arrow">→</div>`;
        }
    });

    html += '</div>';

    html += `
        <div class="killchain-extra">
            <p><strong>Stages detected:</strong> ${Array.from(stages.keys()).join(', ') || 'None'}</p>
            <p><strong>Last update:</strong> ${new Date(entry.lastUpdated).toLocaleTimeString()}</p>
        </div>
        ${breakdownHtml}
    `;

    return html;
}


function computeAlertMetrics() {
    const resolvedAlerts = timelineEvents.filter(e => e.status === 'resolved' && e.acknowledgedAt && e.resolvedAt);
    if (resolvedAlerts.length === 0) {
        return { mtta: null, mttr: null, count: 0 };
    }
    let totalAckTime = 0;
    let totalResolveTime = 0;
    resolvedAlerts.forEach(e => {
        totalAckTime += (e.acknowledgedAt - e.eventTimestamp);
        totalResolveTime += (e.resolvedAt - e.eventTimestamp);
    });
    const count = resolvedAlerts.length;
    return {
        mtta: totalAckTime / count / 60000, 
        mttr: totalResolveTime / count / 60000,
        count
    };
}


function updateAlertMetrics() {
    const metrics = computeAlertMetrics();
    const mtta = metrics.mtta !== null ? metrics.mtta.toFixed(1) : '--';
    const mttr = metrics.mttr !== null ? metrics.mttr.toFixed(1) : '--';
    
    
    document.getElementById('alert-mtta').textContent = mtta;
    document.getElementById('alert-mttr').textContent = mttr;
    document.getElementById('alert-resolved-count').textContent = metrics.count;
    document.getElementById('alert-open-count').textContent = timelineEvents.filter(e => e.status === 'open').length;
    
    
    const dashMtta = document.getElementById('dash-mtta');
    const dashMttr = document.getElementById('dash-mttr');
    if (dashMtta) dashMtta.textContent = mtta;
    if (dashMttr) dashMttr.textContent = mttr;
}
function showKillChain(host) {
    const modal = document.getElementById('killchain-modal');
    const title = document.getElementById('killchain-host');
    const content = document.getElementById('killchain-content');
    if (title) title.textContent = host;
    if (content) {
        content.innerHTML = renderKillChain(host);
    }
    if (modal) modal.classList.remove('hidden');
}

document.getElementById('close-killchain')?.addEventListener('click', () => {
    document.getElementById('killchain-modal').classList.add('hidden');
});

document.getElementById('killchain-modal')?.addEventListener('click', function(e) {
    if (e.target === this) {
        this.classList.add('hidden');
    }
});

const STAGE_CONTRIBUTION = {
    'scan': 20,
    'access': 25,
    'c2': 30,
    'exfil': 30,
    'dns_tunnel': 25,
    'tor': 20,
    'geo': 15
};

async function updateHostRiskHeatmap() {
    const container = document.getElementById('host-risk-heatmap');
    if (!container) return;

    try {
        const res = await fetch('/api/hosts');
        const data = await res.json();
        const hosts = Object.values(data);

        if (!hosts || hosts.length === 0) {
            container.innerHTML = '<div class="heatmap-placeholder">No active hosts detected.</div>';
            return;
        }

        
        const sorted = hosts.sort((a, b) => b.score - a.score);

        let html = '';
        for (const host of sorted) {
            const score = host.score;
            
            let intensity = 0;
            if (score >= 80) intensity = 4;
            else if (score >= 50) intensity = 3;
            else if (score >= 25) intensity = 2;
            else if (score >= 10) intensity = 1;

            const colorClass = score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
            const statusClass = host.status === 'BLOCK' ? 'block' : host.status === 'ALERT' ? 'alert' : 'ok';

            html += `
                <div class="heatmap-tile host-tile" 
                     data-host="${host.host}"
                     data-intensity="${intensity}"
                     data-score="${score.toFixed(1)}"
                     data-status="${host.status}"
                     style="cursor:pointer;"
                     title="${host.host}: ${score.toFixed(1)} (${host.status})">
                    <span class="host-ip">${host.host}</span>
                    <span class="host-score" style="color: ${score >= 80 ? '#ef4444' : score >= 50 ? '#f59e0b' : '#10b981'}">${score.toFixed(1)}</span>
                    <span class="host-status-badge ${statusClass}">${host.status}</span>
                </div>
            `;
        }

        container.innerHTML = html;

        
        container.querySelectorAll('.host-tile').forEach(tile => {
            tile.addEventListener('click', function() {
                const host = this.dataset.host;
                if (host) {
                    showKillChain(host);
                }
            });
        });

    } catch (error) {
        console.error('Error updating host risk heatmap:', error);
        container.innerHTML = '<div class="heatmap-placeholder">Error loading host data.</div>';
    }
}

function renderMitreSummary() {
    const counts = {};
    timelineEvents.forEach(ev => {
        if (ev.mitre) {
            counts[ev.mitre] = (counts[ev.mitre] || 0) + 1;
        }
    });

    const container = document.getElementById('mitre-summary');
    if (!container) return;

    if (Object.keys(counts).length === 0) {
        container.innerHTML = '<p style="color:#6b7280;">No MITRE techniques detected yet.</p>';
        return;
    }

    let html = '<div class="mitre-summary-grid">';
    for (const [tech, count] of Object.entries(counts).sort((a,b) => b[1]-a[1])) {
        const name = MITRE_INFO[tech] || 'Unknown Technique';
        html += `
            <div class="mitre-summary-item">
                <a href="https://attack.mitre.org/techniques/${tech}/" target="_blank">
                    <span class="mitre-tech">${tech}</span>
                    <span class="mitre-name">${name}</span>
                    <span class="mitre-count">${count}</span>
                </a>
            </div>
        `;
    }
    html += '</div>';
    container.innerHTML = html;
}

function correlateAttackChains() {
    const now = Date.now();
    const STALE_TIMEOUT = 30 * 60 * 1000; 

    
    for (const [host, entry] of hostStages.entries()) {
        if (now - entry.lastUpdated > STALE_TIMEOUT) {
            hostStages.delete(host);
        }
    }

    
    for (const [host, entry] of hostStages.entries()) {
        const stages = entry.stages; 

        
        const hasStage = (stage) => stages.has(stage);
        const getTime = (stage) => stages.get(stage) || 0;

        
        if (hasStage('scan') && hasStage('access') && (hasStage('exfil') || hasStage('c2'))) {
            
            const scanTime = getTime('scan');
            const accessTime = getTime('access');
            const finalTime = Math.max(getTime('exfil'), getTime('c2'));
            if (scanTime < accessTime && accessTime < finalTime) {
                const key = `chain:${host}`;
                if (shouldAlert(key, 3600)) {
                   const evidence = {
                      host: host,
                      stages: Array.from(stages.keys()),
                      detectedPattern: 'scan→access→exfil' 
                  };

                  addTimelineEvent(
                      'Multi‑Stage Attack Chain',
                      'critical',
                      `${host} performed reconnaissance, access attempts, and exfiltration/C2 (stages: ${Array.from(stages.keys()).join(' → ')})`,
                      host, null,
                      { stages: Array.from(stages.keys()) },
                      'heuristic',
                      null,
                      evidence
                  );
                }
            }
        }

        
        if (hasStage('scan') && hasStage('access') && !hasStage('exfil') && !hasStage('c2')) {
            const key = `suspicious:${host}`;
            if (shouldAlert(key, 3600)) {
                addTimelineEvent(
                    'Suspicious Activity Pattern',
                    'high',
                    `${host} performed scanning and brute force attempts (stages: ${Array.from(stages.keys()).join(' → ')})`,
                    host,
                    null,
                    { stages: Array.from(stages.keys()) },
                    'heuristic'
                );
            }
        }

        
        if (hasStage('c2') && hasStage('exfil')) {
            const key = `c2exfil:${host}`;
            if (shouldAlert(key, 3600)) {
                addTimelineEvent(
                    'Data Exfiltration via C2',
                    'critical',
                    `${host} used C2 communication and performed data exfiltration`,
                    host,
                    null,
                    { stages: Array.from(stages.keys()) },
                    'heuristic'
                );
            }
        }

        
        if (hasStage('tor') && hasStage('exfil')) {
            const key = `torexfil:${host}`;
            if (shouldAlert(key, 3600)) {
                addTimelineEvent(
                    'Exfiltration via Tor',
                    'high',
                    `${host} used Tor and performed data exfiltration`,
                    host,
                    null,
                    { stages: Array.from(stages.keys()) },
                    'heuristic'
                );
            }
        }

        
        if (hasStage('dns_tunnel') && hasStage('exfil')) {
            const key = `dnsexfil:${host}`;
            if (shouldAlert(key, 3600)) {
                addTimelineEvent(
                    'DNS Tunneling for Exfiltration',
                    'high',
                    `${host} used DNS tunneling and performed data exfiltration`,
                    host,
                    null,
                    { stages: Array.from(stages.keys()) },
                    'heuristic'
                );
            }
        }

        
        if (hasStage('geo') && hasStage('c2')) {
            const key = `geoc2:${host}`;
            if (shouldAlert(key, 3600)) {
                addTimelineEvent(
                    'High-Risk Geolocation with C2',
                    'high',
                    `${host} communicates with high-risk regions and exhibits C2 behaviour`,
                    host,
                    null,
                    { stages: Array.from(stages.keys()) },
                    'heuristic'
                );
            }
        }
    }
}



function detectPortScans(packetList = globalPacketData) {
    const srcTargets = new Map(); 
    const srcPorts = new Map();   

    
    for (const pkt of packetList) {
        if (!pkt.dst_port) continue;
        if (!srcTargets.has(pkt.src)) srcTargets.set(pkt.src, new Set());
        srcTargets.get(pkt.src).add(pkt.dst);
        if (!srcPorts.has(pkt.src)) srcPorts.set(pkt.src, new Set());
        srcPorts.get(pkt.src).add(pkt.dst_port);
    }

    
    for (const [src, targets] of srcTargets.entries()) {
        const ports = srcPorts.get(src) || new Set();
        const targetCount = targets.size;
        const portCount = ports.size;

        if (targetCount >= 10 && portCount <= 3) {
            const key = `hscan:${src}`;
            if (!shouldAlert(key, PORT_SCAN_COOLDOWN)) continue;

            const severity = computeSeverity(targetCount, 10, 25, 50);
            
            let confidence = 40 + (targetCount / 10) * 30;
            if (blockedIPs.has(src)) confidence += 20;
            confidence = Math.min(100, confidence);

            const evidence = {
                targetCount: targetCount,
                portCount: portCount,
                sourceIP: src,
                isBlacklisted: blockedIPs.has(src),
                mitre: MITRE_MAP['Horizontal Port Scan'] || null
            };

            incrementStat('portScan');

            addTimelineEvent(
                'Horizontal Port Scan',
                severity,
                `${src} scanned ${targetCount} hosts on ${portCount} ports`,
                src,
                null,
                { targetCount, portCount },
                confidence,
                'heuristic',
                evidence
            );
        }
    }

    
    for (const [src, ports] of srcPorts.entries()) {
        const targets = srcTargets.get(src) || new Set();
        const portCount = ports.size;
        const targetCount = targets.size;

        if (portCount >= 15) {
            const key = `vscan:${src}`;
            if (!shouldAlert(key, PORT_SCAN_COOLDOWN)) continue;

            const severity = computeSeverity(portCount, 15, 30, 60);
            
            let confidence = 40 + (portCount / 15) * 30;
            if (blockedIPs.has(src)) confidence += 20;
            confidence = Math.min(100, confidence);

            incrementStat('portScan');

            const evidence = {
                targetCount: targetCount,
                portCount: portCount,
                sourceIP: src,
                isBlacklisted: blockedIPs.has(src),
                mitre: MITRE_MAP['Vertical Port Scan'] || null
            };

            addTimelineEvent(
                'Vertical Port Scan',
                severity,
                `${src} scanned ${portCount} ports on ${targetCount} hosts`,
                src,
                null,
                { portCount, targetCount },
                confidence,
                'heuristic',
                evidence
                
            );
        }
    }
}


const BRUTE_SENSITIVE_PORTS = [22, 3389, 445, 3306, 1433, 5432, 27017]; 

function detectBruteForce(packetList = globalPacketData) {
    const now = Date.now();
    
    const recent = packetList.filter(p => p.timestamp >= now - BRUTE_FORCE_WINDOW);

    
    const targetAttempts = new Map(); 

    for (const pkt of recent) {
        if (!BRUTE_SENSITIVE_PORTS.includes(Number(pkt.dst_port))) continue;
        if (pkt.proto !== 'TCP') continue;
        
        

        const key = `${pkt.src}->${pkt.dst}:${pkt.dst_port}`;
        targetAttempts.set(key, (targetAttempts.get(key) || 0) + 1);
    }

    
    for (const [key, count] of targetAttempts.entries()) {
        if (count < BRUTE_FORCE_THRESHOLD) continue;
        const [src, rest] = key.split('->');
        const alertKey = `bruteforce:${src}`; 
        if (shouldAlert(alertKey, BRUTE_FORCE_COOLDOWN)) {
            const severity = computeSeverity(count, 20, 40, 80);
            
           let confidence = 50 + (count / BRUTE_FORCE_THRESHOLD) * 30;
            if (BRUTE_SENSITIVE_PORTS.includes(Number(rest.split(':')[1]))) confidence += 10;
            confidence = Math.min(100, confidence);

            const evidence = {
                attempts: count,
                targetHost: rest.split(':')[0],
                targetPort: parseInt(rest.split(':')[1]),
                isSensitivePort: BRUTE_SENSITIVE_PORTS.includes(Number(rest.split(':')[1])),
                mitre: MITRE_MAP['Brute Force Attempt'] || null
            };

            incrementStat('bruteForce');
            addTimelineEvent(
                'Brute Force Attempt',
                severity,
                `${src} made ${count} connection attempts to ${rest} in the last minute`,
                src,
                rest.split(':')[0], 
                { attempts: count },
                confidence,
                'heuristic',
                evidence
            );
        }
    }
}



function detectBeaconing(packetList = globalPacketData) {
    const flowTimestamps = new Map();

    for (const pkt of packetList) {
        if (!pkt.dst) continue;
        
        if (pkt.dst.startsWith("255.") || pkt.dst.startsWith("224.")) continue;
        
        
        const key = `${pkt.src}→${pkt.dst}`;
        if (!flowTimestamps.has(key)) flowTimestamps.set(key, []);
        flowTimestamps.get(key).push(pkt.timestamp);
    }

    for (const [flow, timestamps] of flowTimestamps.entries()) {
        if (timestamps.length < BEACON_MIN_CONNECTIONS) continue;
        timestamps.sort((a, b) => a - b);

        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        const avgInterval = intervals.reduce((s, v) => s + v, 0) / intervals.length;
        if (avgInterval === 0) continue;

        const variance = intervals.reduce((s, v) => s + Math.pow(v - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);
        const varianceRatio = stdDev / avgInterval;   

        if (varianceRatio > BEACON_MAX_VARIANCE_RATIO) continue;

        const duration = timestamps[timestamps.length - 1] - timestamps[0];
        if (duration < BEACON_MIN_DURATION) continue;

        const [src, dst] = flow.split('→');
        const key = `beacon:${src}:${dst}`;

        if (shouldAlert(key, BEACON_COOLDOWN)) {
        const severity = computeSeverity(timestamps.length, 3, 6, 10);
        let confidence = 40 + (timestamps.length / BEACON_MIN_CONNECTIONS) * 20;
        if (varianceRatio < 0.15) confidence += 20;
        if (duration > 120000) confidence += 20;
        confidence = Math.min(100, confidence);

        const evidence = {
            packetCount: timestamps.length,
            avgIntervalSec: Math.round(avgInterval / 1000),
            varianceRatio: varianceRatio,
            durationSec: Math.round(duration / 1000),
            destinationPort: dst_port,
            isIOC: blockedIPs.has(dst),
            mitre: MITRE_MAP['Beaconing'] || null
        };

        incrementStat('beaconing');
        addTimelineEvent(
            'Beaconing',
            severity,
            `${src} → ${dst} communicates regularly (every ${Math.round(avgInterval/1000)}s)`,
            src,
            dst,
            { intervalSec: Math.round(avgInterval/1000), packets: timestamps.length },
            confidence,
            'heuristic',
            null,    
            evidence 
        );
    }
}
}

function detectBeaconing(timestamps) {
    if (timestamps.length < 4) return null;
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    const commonIntervals = [30000, 60000, 300000];
    for (const target of commonIntervals) {
        const matches = intervals.filter(interval => Math.abs(interval - target) < target * 0.2);
        if (matches.length >= 3) {
            return {
                interval: target,
                count: matches.length,
                description: `Regular communication every ${target/1000}s (${matches.length} intervals)`
            };
        }
    }
    return null;
}

function computeSeverity(count, thresholdLow=20, thresholdHigh=40, thresholdCrit=80) {
    if (count >= thresholdCrit) return 'critical';
    if (count >= thresholdHigh) return 'high';
    if (count >= thresholdLow) return 'medium';
    return 'low';
}


function isSuspiciousDnsQuery(payload) {
    if (!payload) return false;
    const parts = payload.split('.');
    if (parts.length > 5) return true;
    if (parts[0] && parts[0].length > 20) return true;
    
    const chars = new Set(payload);
    if (chars.size / payload.length > 0.7) return true;
    return false;
}

function detectDnsTunneling(packetList = globalPacketData) {
    const now = Date.now();
    const dnsRequests = new Map(); 

    for (const pkt of packetList) {
        
        if (pkt.dst_port !== 53 || pkt.proto !== 'UDP') continue;
        
        if (now - pkt.timestamp > DNS_TUNNELING_WINDOW) continue;
        
        if (!isSuspiciousDnsQuery(pkt.payload)) continue;
        
        dnsRequests.set(pkt.src, (dnsRequests.get(pkt.src) || 0) + 1);
    }

    for (const [src, count] of dnsRequests.entries()) {
        if (count >= DNS_TUNNELING_THRESHOLD) {
            const key = `dnstunnel:${src}`;
            if (shouldAlert(key, DNS_TUNNELING_COOLDOWN)) {
                const severity = computeSeverity(count, 50, 100, 200);
                
               let confidence = 50 + (count / DNS_TUNNELING_THRESHOLD) * 30;
               if (count > 150) confidence += 20;
               confidence = Math.min(100, confidence);
                incrementStat('dnsTunneling');
                addTimelineEvent(
                    'Potential DNS Tunneling',
                    severity,
                    `${src} made ${count} suspicious DNS queries in the last minute`,
                    src,
                    null,
                    { dnsCount: count, windowSec: DNS_TUNNELING_WINDOW / 1000 },
                    confidence,
                    'heuristic'
                );
            }
        }
    }
}


function detectDataExfiltration(packetList = globalPacketData) {
    
    const now = Date.now();
    const cutoff = now - EXFIL_WINDOW_MS;
    
    
    const outboundBytes = new Map(); 
    const destinations = new Set();       
    const sourceDestCounts = new Map();

    for (const pkt of globalPacketData) {
        
        if (!pkt.timestamp || pkt.timestamp < cutoff) continue;
        
        
        if (isPrivateIP(pkt.src) && !isPrivateIP(pkt.dst)) {
            
            let packetSize = pkt.size || (pkt.payload ? pkt.payload.length : 0) + 100;
            outboundBytes.set(pkt.src, (outboundBytes.get(pkt.src) || 0) + packetSize);

            destinations.add(pkt.dst);
            if (!sourceDestCounts.has(pkt.src)) sourceDestCounts.set(pkt.src, new Set());
            sourceDestCounts.get(pkt.src).add(pkt.dst);
        }
    }

    
    if (outboundBytes.size > 0) {
        console.log("Exfil rolling window:", [...outboundBytes.entries()].map(([src, bytes]) => 
            `${src}: ${(bytes/(1024*1024)).toFixed(2)} MB`
        ).join(", "));
    }

    for (const [src, bytes] of outboundBytes.entries()) {
        if (bytes >= EXFIL_OUTBOUND_THRESHOLD_BYTES) {
            const key = `exfil:${src}`;
            if (shouldAlert(key, EXFIL_COOLDOWN)) {
                const mb = bytes / (1024 * 1024);
                const severity = computeSeverity(mb, 10, 50, 100);
                let confidence = 40 + (mb / 50) * 40;
                if (mb > 100) confidence += 20;
                confidence = Math.min(100, confidence);

                 const uniqueDests = sourceDestCounts.get(src)?.size || 0;
                 const evidence = {
                    megabytesSent: mb,
                    windowMinutes: EXFIL_WINDOW_MS / 60000,
                    outboundDestinations: uniqueDests,
                    mitre: MITRE_MAP['Possible Data Exfiltration'] || null
                };

                addTimelineEvent(
                    'Possible Data Exfiltration',
                    severity,
                    `${src} sent ${mb.toFixed(1)} MB to external destinations in the last ${EXFIL_WINDOW_MS / 60000} minutes`,
                    src,
                    null,
                    { megabytes: mb.toFixed(1) },
                    confidence,
                    'heuristic',
                    evidence
                );
            }
        }
    }
}

const HIGH_RISK_COUNTRIES = new Set(['KP', 'IS', 'SY', 'RU', 'CN', 'CU', 'VE']);
const GEO_COOLDOWN = 1800; 

function detectSuspiciousGeo(packetList = globalPacketData) {
    const seen = new Set(); 

    for (const pkt of packetList) {
        
        if (!isPrivateIP(pkt.src) || isPrivateIP(pkt.dst)) continue;

        const dstGeo = geoCache.get(pkt.dst);
        if (!dstGeo || !HIGH_RISK_COUNTRIES.has(dstGeo.code)) continue;

        const key = `geo:${pkt.src}:${dstGeo.code}`;
        if (!shouldAlert(key, GEO_COOLDOWN)) continue;

        
        const severity = dstGeo.code === 'KP' ? 'critical' : 'medium';

        incrementStat('suspiciousGeo'); 

        const evidence = {
          countryCode: dstGeo.code,
          countryName: dstGeo.name,
          isHighRisk: HIGH_RISK_COUNTRIES.has(dstGeo.code),
          mitre: MITRE_MAP['Suspicious Geolocation'] || null
      };

      addTimelineEvent(
          'Suspicious Geolocation',
          severity,
          `${pkt.src} connected to ${pkt.dst} (${dstGeo.name}, ${dstGeo.code})`,
          pkt.src, pkt.dst,
          { countryCode: dstGeo.code, countryName: dstGeo.name },
          'heuristic',
          null,
          evidence
      );
    }
}


let TOR_EXIT_NODES = new Set();   
const TOR_DETECTION_WINDOW = 60000;
const TOR_COOLDOWN = 600;      

function detectTorConnections(packetList = globalPacketData) {
    if (TOR_EXIT_NODES.size === 0) return;

    const now = Date.now();
    const seen = new Set(); 

    for (const pkt of packetList) {
        if (now - pkt.timestamp > TOR_DETECTION_WINDOW) continue;

        let torIP = null;
        if (TOR_EXIT_NODES.has(pkt.dst)) {
            torIP = pkt.dst;
        } else if (TOR_EXIT_NODES.has(pkt.src)) {
            torIP = pkt.src;
        }
        if (!torIP) continue;

        
        const seenKey = `${pkt.src}:${torIP}`;
        if (seen.has(seenKey)) continue;
        seen.add(seenKey);

        const alertKey = `tor:${pkt.src}`;
        if (shouldAlert(alertKey, TOR_COOLDOWN)) {
            
            const direction = (pkt.src === torIP) ? 'from' : 'to';
            incrementStat('torConnection');

           const evidence = {
                torExitNode: torIP,
                direction: direction,
                mitre: MITRE_MAP['Tor Connection'] || null
            };

            addTimelineEvent(
                'Tor Connection',
                'medium',
                `${pkt.src} communicated ${direction} Tor exit node ${torIP}`,
                pkt.src, torIP,
                null,
                'heuristic',
                null,
                evidence
            );
        }
    }
}

const C2_MAX_PACKET_SIZE = 200;     
const C2_MIN_SMALL_PACKET_RATIO = 0.8; 

function detectC2(packetList = globalPacketData) {
    if (blockedIPs.size === 0) return;

    const flowData = new Map(); 

    for (const pkt of packetList) {
        if (!pkt.dst || !pkt.src) continue;
        
        if (!isPrivateIP(pkt.src) || isPrivateIP(pkt.dst)) continue;
        
        if (!blockedIPs.has(pkt.dst)) continue;
        
        if (pkt.dst.startsWith("255.") || pkt.dst.startsWith("224.")) continue;

        const key = `${pkt.src}→${pkt.dst}`;
        if (!flowData.has(key)) {
            flowData.set(key, { timestamps: [], sizes: [] });
        }
        const entry = flowData.get(key);
        entry.timestamps.push(pkt.timestamp);
        entry.sizes.push(pkt.size || 0);
    }

    for (const [flow, data] of flowData.entries()) {
        let { timestamps, sizes } = data;
        if (timestamps.length < C2_MIN_CONNECTIONS) continue;

        timestamps.sort((a, b) => a - b);

        
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }
        const avgInterval = intervals.reduce((s, v) => s + v, 0) / intervals.length;
        if (avgInterval === 0) continue;

        
        const variance = intervals.reduce((s, v) => s + Math.pow(v - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);
        const varianceRatio = stdDev / avgInterval;
        if (varianceRatio > C2_MAX_VARIANCE_RATIO) continue;

        
        const duration = timestamps[timestamps.length - 1] - timestamps[0];
        if (duration < C2_MIN_DURATION) continue;

        
        const smallPackets = sizes.filter(s => s <= C2_MAX_PACKET_SIZE).length;
        if (smallPackets / sizes.length < C2_MIN_SMALL_PACKET_RATIO) continue;

        const [src, dst] = flow.split('→');
        const key = `c2:${src}:${dst}`;
        if (shouldAlert(key, C2_COOLDOWN)) {
            const severity = computeSeverity(timestamps.length, 3, 6, 10);
            
            let confidence = 60;
            if (varianceRatio < 0.15) confidence += 15;
            if (avgInterval < 10000) confidence += 10;
            if (duration > 120000) confidence += 15;
            confidence = Math.min(100, confidence);
            incrementStat('c2Detection');

            const evidence = {
                packetCount: timestamps.length,
                avgIntervalSec: Math.round(avgInterval / 1000),
                varianceRatio: varianceRatio,
                durationSec: Math.round(duration / 1000),
                avgPacketSize: Math.round(sizes.reduce((a,b) => a+b, 0) / sizes.length),
                destinationIP: dst,
                isMalicious: true,
                mitre: MITRE_MAP['Beaconing to Malicious Host'] || null
            };

            addTimelineEvent(
                'Beaconing to Malicious Host',
                severity,
                `${src} → ${dst} communicates regularly to known malicious IP (small packets, every ${Math.round(avgInterval/1000)}s)`,
                src, dst,
                {
                    intervalSec: Math.round(avgInterval / 1000),
                    packets: timestamps.length,
                    avgSize: Math.round(sizes.reduce((a,b) => a+b, 0) / sizes.length)
                },
                confidence,
                'heuristic',
                null,
                evidence
            );
        }
    }
}


const intelCache = new Map(); 

async function fetchIPInfo(ip) {
    
    if (intelCache.has(ip)) {
        const cached = intelCache.get(ip);
        if (Date.now() - cached.timestamp < 3600000) { 
            return cached.data;
        }
    }
    try {
        const response = await fetch(`/api/ip_info/${ip}`);
        if (!response.ok) throw new Error('Failed to fetch IP info');
        const data = await response.json();
        intelCache.set(ip, { data, timestamp: Date.now() });
        return data;
    } catch (error) {
        console.warn('IP info fetch error:', error);
        return null;
    }
}



function reputationBadge(rep) {
    switch(rep) {
        case 'malicious':
            return '<span class="rep-badge malicious">🔴 MALICIOUS</span>';
        case 'suspicious':
            return '<span class="rep-badge suspicious">🟡 SUSPICIOUS</span>';
        case 'clean':
            return '<span class="rep-badge benign">🟢 BENIGN</span>';
        default:
            return '<span class="rep-badge unknown">⚫ UNKNOWN</span>';
    }
}


function riskLevel(score) {
    if (score === undefined || score === null) return 'UNKNOWN';
    if (score >= 75) return 'HIGH 🔴';
    if (score >= 40) return 'MEDIUM 🟡';
    if (score >= 10) return 'LOW 🟢';
    return 'NONE ⚪';
}

function renderIPInfo(ip, info) {
    if (!info) return '<p>No information available.</p>';

    const flag = getFlagEmoji ? getFlagEmoji(info.country_code) : '';
    const countryDisplay = flag ? `${flag} ${info.country}` : info.country;

    const relatedEvents = timelineEvents.filter(e => e.src === ip || e.dst === ip);
    let historyHtml = '<p>No recent activity.</p>';
    if (relatedEvents.length > 0) {
        const latest = relatedEvents.slice(0, 5).map(e =>
            `<li><span class="severity-${e.severity}">${e.severity.toUpperCase()}</span> ${e.eventType} (${formatAlertTime(e)})</li>`
        ).join('');
        historyHtml = `<ul style="list-style:none; padding:0; margin:0;">${latest}</ul>`;
    }

    const links = `
        <div class="ip-intel-links">
            <a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank">VirusTotal</a>
            <a href="https://www.abuseipdb.com/check/${ip}" target="_blank">AbuseIPDB</a>
            <a href="https://www.shodan.io/host/${ip}" target="_blank">Shodan</a>
            <a href="https://www.greynoise.io/viz/ip/${ip}" target="_blank">GreyNoise</a>
        </div>
    `;

    const copyBtn = `<button class="copy-ip-btn" data-ip="${ip}" onclick="navigator.clipboard.writeText('${ip}'); showToast('IP copied to clipboard!', 'success');">📋 Copy IP</button>`;

    const repBadge = reputationBadge(info.reputation);
    const risk = riskLevel(info.abuse_score);

    let html = `<div class="ip-intel-panel">`;
    html += `<div class="ip-intel-header">`;
    html += `<h4>${ip}</h4>`;
    html += `${copyBtn}`;
    html += `</div>`;

    html += `<table class="ip-intel-table">`;
    html += `<tr><td>Country</td><td>${countryDisplay}</td></tr>`;
    html += `<tr><td>City</td><td>${info.city || 'Unknown'}</td></tr>`;
    html += `<tr><td>ISP</td><td>${info.isp || 'Unknown'}</td></tr>`;
    html += `<tr><td>Organisation</td><td>${info.org || 'Unknown'}</td></tr>`;
    html += `<tr><td>ASN</td><td>${info.asn || 'Unknown'}</td></tr>`;
    html += `<tr><td>Tor Exit</td><td>${info.tor ? '✅ Yes' : '❌ No'}</td></tr>`;
    html += `<tr><td>Reputation</td><td>${repBadge}</td></tr>`;
    if (info.abuse_score !== undefined && info.abuse_score !== null) {
        html += `<tr><td>Abuse Score</td><td>${info.abuse_score} (${risk})</td></tr>`;
    }
    if (info.abuse_categories && info.abuse_categories.length) {
        html += `<tr><td>Abuse Categories</td><td>${info.abuse_categories.join(', ')}</td></tr>`;
    }
    html += `</table>`;

    html += `<div class="ip-intel-history">`;
    html += `<h5>Recent Activity</h5>`;
    html += historyHtml;
    html += `</div>`;

    html += `<div class="ip-intel-links">`;
    html += links;
    html += `</div>`;

    html += `</div>`;
    return html;
}

async function showIPInfo(ip) {
    if (!ip) return;
    const info = await fetchIPInfo(ip);
    if (!info) {
        showToast('Could not fetch IP information.', 'danger');
        return;
    }
    const modal = document.getElementById('ip-intel-modal');
    const content = document.getElementById('ip-intel-content');
    if (modal && content) {
        content.innerHTML = renderIPInfo(ip, info);
        modal.classList.remove('hidden');
    }
}


document.addEventListener('click', async function(e) {
    const target = e.target.closest('.ip-intel-trigger');
    if (!target) return;
    const ip = target.dataset.ip;
    if (!ip) return;
    e.preventDefault();
    showIPInfo(ip);
});


document.getElementById('close-ip-intel')?.addEventListener('click', () => {
    document.getElementById('ip-intel-modal').classList.add('hidden');
});

function runThreatDetection() {
    if (globalPacketData.length === 0) return;
    const now = Date.now();

    const newPackets = globalPacketData.filter(pkt => pkt.timestamp > lastDetectionTime);
    if (newPackets.length > 0) {
        lastDetectionTime = now;
        detectPortScans(newPackets);
        detectBruteForce(newPackets);
    }

    const fiveMinutesAgo = now - 5 * 60 * 1000;
    const beaconPackets = globalPacketData.filter(p => p.timestamp >= fiveMinutesAgo);
    detectBeaconing(beaconPackets);

    const oneMinuteAgo = now - 60 * 1000;
    const dnsPackets = globalPacketData.filter(p => p.timestamp >= oneMinuteAgo);
    detectDnsTunneling(dnsPackets);

    const tenMinutesAgo = now - 10 * 60 * 1000;
    const exfilPackets = globalPacketData.filter(p => p.timestamp >= tenMinutesAgo);
    detectDataExfiltration(exfilPackets);

    detectSuspiciousGeo(globalPacketData); 

    const c2Window = now - 10 * 60 * 1000;
    const c2Packets = globalPacketData.filter(p => p.timestamp >= c2Window);
    detectC2(c2Packets);

    const torWindow = now - 60 * 1000;
    const torPackets = globalPacketData.filter(p => p.timestamp >= torWindow);
    detectTorConnections(torPackets);

    correlateAttackChains();
    matchIOCs();
    matchRules();
    renderMitreSummary();
    renderMitreCoverage();
    updateAssetAlertCounts();
    updateUEBA();
    correlateAlerts();
    renderIncidentsTable();
}


function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const char of str) freq[char] = (freq[char] || 0) + 1;
    const len = str.length;
    let entropy = 0;
    for (const c in freq) {
        const p = freq[c] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}



function getPortFrequency(port) {
    if (!port) return 0;
    if (!window._portFreq) rebuildPortFreq();
    return window._portFreq.get(port) || 0;
}

function getPortRarityCategory(port) {
    const freq = getPortFrequency(port);
    if (freq === 0) return 'Unknown';
    if (freq <= 2) return '🔴 Rare';
    if (freq <= 10) return '🟠 Uncommon';
    if (freq <= 50) return '🟡 Common';
    return '🟢 Very Common';
}


function showPacketDrilldown(ev) {
    const modal = document.getElementById('packet-drilldown-modal');
    const content = document.getElementById('drilldown-content');
    if (!modal || !content) return;

    
    const eventTime = ev.eventTimestamp || Date.now();
    const windowSize = getEventWindowSize(ev.eventType);
    const relatedPackets = globalPacketData.filter(p => {
    const pTime = p.timestamp || 0;
      if (Math.abs(pTime - eventTime) > windowSize) return false;
      if (ev.src && p.src !== ev.src && p.dst !== ev.src) return false;
      if (ev.dst && p.src !== ev.dst && p.dst !== ev.dst) return false;
      return true;
    });

    
    relatedPackets.sort((a, b) => (b.timestamp || 0) - (formatAlertTime(a) || 0));

    
    let chainHtml = '';
    if (ev.src && hostStages.has(ev.src)) {
        const entry = hostStages.get(ev.src);
        const stages = entry.stages; 
        const completedPhases = new Set();
        for (const [stage, _] of stages.entries()) {
            const phase = PHASE_MAP[stage];
            if (phase) completedPhases.add(phase);
        }
        const total = PHASE_ORDER.length;
        const done = completedPhases.size;
        const progress = Math.round((done / total) * 100);
        chainHtml = `
            <div class="drilldown-chain">
                <strong>Attack Chain Progress for ${ev.src}:</strong>
                <div class="mini-chain">
                    ${PHASE_ORDER.map(p => {
                        const done = completedPhases.has(p);
                        return `<span class="mini-phase ${done ? 'done' : 'pending'}">${p}</span>`;
                    }).join(' → ')}
                </div>
                <span>${done}/${total} phases (${progress}%)</span>
            </div>
        `;
    }

    
    let summaryHtml = '';
    if (ev.src) {
        const hostInfo = mlInfoMap.get(ev.src);
        const hostStagesEntry = hostStages.get(ev.src);
        const completedPhases = hostStagesEntry ? new Set([...hostStagesEntry.stages.keys()].map(s => PHASE_MAP[s])) : new Set();
        const totalPhases = PHASE_ORDER.length;
        const done = completedPhases.size;
        const progress = Math.round((done / totalPhases) * 100);
        const blockedCount = relatedPackets.filter(p => blockedIPs.has(p.dst) || blockedIPs.has(p.src)).length;

        const mitreList = ev.mitre ? ev.mitre : '—';
        summaryHtml = `
            <div class="drilldown-summary">
                <h4>Investigation Summary</h4>
                <div class="summary-grid">
                    <div><strong>Host:</strong> ${ev.src}</div>
                    <div><strong>Risk:</strong> ${hostInfo ? hostInfo.score.toFixed(1) : 'Unknown'}</div>
                    <div><strong>Status:</strong> ${hostInfo ? hostInfo.status : 'Unknown'}</div>
                    <div><strong>MITRE:</strong> ${mitreList}</div>
                    <div><strong>Attack Chain Progress:</strong> ${done}/${totalPhases} (${progress}%)</div>
                    <div><strong>Related Packets:</strong> ${relatedPackets.length}</div>
                    <div><strong>Blocked Connections:</strong> ${blockedCount}</div>
                </div>
            </div>
        `;
    }

    
    let html = `<div class="drilldown-event">`;
    html += `<h4>${ev.eventType}</h4>`;
    html += `<div class="drilldown-meta">`;
    html += `<span><strong>Time:</strong> ${formatAlertTime(ev)}</span>`;
    const severity = ev.severity || 'low';
    html += `<span><strong>Severity:</strong> <span class="severity-${severity}">${severity.toUpperCase()}</span></span>`;
    if (ev.mitre) html += `<span><strong>MITRE:</strong> ${ev.mitre}</span>`;
    if (ev.confidence !== undefined) html += `<span><strong>Confidence:</strong> ${Math.round(ev.confidence)}%</span>`;
    html += `</div>`;
    html += `<p><strong>Details:</strong> ${ev.details}</p>`;
    html += `<p><strong>Related Packets:</strong> ${relatedPackets.length}</p>`;
    if (chainHtml) html += chainHtml;
    html += `</div>`;

    html += summaryHtml;

   
if (relatedPackets.length === 0) {
    html += `<p class="text-muted">No related packets found.</p>`;
} else {
    html += `<div class="drilldown-packets"><table class="packet-table">`;
    html += `<thead><tr>
        <th>Time</th>
        <th>Source</th>
        <th>Dest</th>
        <th>Proto</th>
        <th>Port</th>
        <th>Size</th>
        <th>Classification</th>
        <th>Entropy</th>
        <th>Port Rarity</th>
        <th>Payload</th>
    </tr></thead><tbody>`;

    relatedPackets.forEach(p => {
        const fullPayload = p.payload ? sanitize(p.payload) : '';
        const shortPayload = fullPayload.length > 30 ? fullPayload.slice(0,30)+'...' : fullPayload;
        const hasPayload = fullPayload.length > 0;
        const mlInfo = mlInfoMap.get(p.src) || mlInfoMap.get(p.dst);
        const mlLabel = mlInfo ? mlInfo.label : '—';
        const entropy = calculateEntropy(p.payload || '');
        const portRarity = getPortRarityCategory(p.dst_port);
        const isMalicious = blockedIPs.has(p.src) || blockedIPs.has(p.dst);
        const repBadge = isMalicious ? '🚫' : (mlLabel === 'MALICIOUS' ? '⚠️' : '');
        const payloadBtn = hasPayload ?
            `<button class="payload-view-btn" data-payload="${encodeURIComponent(fullPayload)}" title="View full payload">📄</button>` :
            '—';

        const rawBtn = `<button class="payload-view-btn raw-btn" data-packet-id="${p.id}" title="View Raw Packet"><i class="fas fa-code"></i></button>`;

        html += `<tr class="${ev.src && (p.src === ev.src || p.dst === ev.src) ? 'suspicious-packet' : ''}">
            <td>${p.time}</td>
            <td><span class="ip-intel-trigger" data-ip="${p.src}">${p.src}</span></td>
            <td><span class="ip-intel-trigger" data-ip="${p.dst}">${p.dst}</span></td>
            <td>${p.proto}</td>
            <td>${p.dst_port || 'any'}</td>
            <td>${p.size || '—'}</td>
            <td>${mlLabel}</td>
            <td>${entropy > 0 ? entropy.toFixed(2) : '—'}</td>
            <td>${portRarity}</td>
            <td>${shortPayload || 'n/a'} ${payloadBtn} ${rawBtn}</td>
        </tr>`;
    });

    html += `</tbody></table></div>`;
}

    
    html += `<div class="drilldown-actions">`;
    html += `<button id="export-drilldown-btn" class="btn-secondary">📥 Export Evidence (JSON)</button>`;
    html += `</div>`;

    content.innerHTML = html;
    modal.classList.remove('hidden');

    
    document.getElementById('export-drilldown-btn')?.addEventListener('click', function() {
        const exportData = {
            event: ev,
            relatedPackets: relatedPackets,
            exportedAt: new Date().toISOString()
        };
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `drilldown-${ev.eventType}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    content.querySelectorAll('.raw-btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        const packetId = this.dataset.packetId;
        const pkt = globalPacketData.find(p => p.id === packetId);
        if (pkt) {
            showRawPacketView(pkt);
        }
    });
});

    
    content.querySelectorAll('.payload-view-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const encoded = this.dataset.payload;
            if (!encoded) return;
            const payload = decodeURIComponent(encoded);
            showPayloadModal(payload);
        });
    });
}

function getEventWindowSize(eventType) {
    const map = {
        'Beaconing': 300000,                 
        'Beaconing to Malicious Host': 300000,
        'Possible Data Exfiltration': 600000, 
        'Data Exfiltration': 600000,
        'Brute Force Attempt': 120000,        
        'Horizontal Port Scan': 60000,        
        'Vertical Port Scan': 60000,
        'Multi-Stage Attack Chain': 600000,   
        'Suspicious Activity Pattern': 600000,
        
    };
    return map[eventType] || 10000;
}

function showPayloadModal(payload) {
    const modal = document.getElementById('payload-modal');
    const content = document.getElementById('payload-content');
    if (!modal || !content) return;
    content.textContent = payload || '(empty payload)';
    modal.classList.remove('hidden');
}
document.getElementById('close-payload-modal')?.addEventListener('click', () => {
    document.getElementById('payload-modal').classList.add('hidden');
});
document.getElementById('payload-modal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
});

document.getElementById('close-drilldown')?.addEventListener('click', () => {
    document.getElementById('packet-drilldown-modal').classList.add('hidden');
});

document.getElementById('packet-drilldown-modal')?.addEventListener('click', function(e) {
    if (e.target === this) {
        this.classList.add('hidden');
    }
});

document.addEventListener('click', async function(e) {
    const target = e.target.closest('.ip-intel-trigger');
    if (!target) return;
    const ip = target.dataset.ip;
    if (!ip) return;
    
    const info = await fetchIPInfo(ip);
    if (!info) {
        showToast('Could not fetch IP information.', 'danger');
        return;
    }
    
    
    const modal = document.getElementById('ip-intel-modal');
    const content = document.getElementById('ip-intel-content');
    if (modal && content) {
        content.innerHTML = renderIPInfo(ip, info);
        modal.classList.remove('hidden');
    }
});

document.addEventListener('click', function(e) {
    const btn = e.target.closest('.ip-intel-btn');
    if (btn) {
        e.preventDefault();
        const ip = btn.dataset.ip;
        if (ip) {
            showIPInfo(ip);
        }
    }
});

function applyFilters(data) {
  const protocol = document.getElementById('protocolFilter').value.toLowerCase();
  const src = document.getElementById('srcFilter').value;
  const dst = document.getElementById('dstFilter').value;
  const srcPort = document.getElementById('srcPortFilter').value;
  const dstPort = document.getElementById('dstPortFilter').value;
  const exactTime = document.getElementById('exactTime').value;
  const startTime = document.getElementById('startTime').value;
  const endTime = document.getElementById('endTime').value;
  const payloadContent = document.getElementById('payloadFilter').value.toLowerCase();

  const startTimeWithSeconds = startTime ? startTime + ':00' : null;
  const endTimeWithSeconds = endTime ? endTime + ':00' : null;

  return data.filter(packet => {
    const packetTime = packet.time || '';

    const matchesStartTime = !startTimeWithSeconds || packetTime >= startTimeWithSeconds;
    const matchesEndTime = !endTimeWithSeconds || packetTime <= endTimeWithSeconds;
    const matchesProtocol = !protocol || (packet.proto && packet.proto.toLowerCase().includes(protocol));
    const matchesSrc = !src || packet.src.includes(src);
    const matchesDst = !dst || packet.dst.includes(dst);
    const matchesSrcPort = !srcPort || packet.src_port === Number(srcPort);
    const matchesDstPort = !dstPort || packet.dst_port === Number(dstPort);
    const matchesPayload = !payloadContent || 
    (packet.payload && packet.payload.toLowerCase().includes(payloadContent));

    if (exactTime) {
      return packetTime === exactTime;
    }

    return matchesStartTime && matchesEndTime && matchesProtocol &&
           matchesSrc && matchesDst && matchesSrcPort && matchesDstPort && matchesPayload;
  });
}

const portColors = {}; 

function updateChartsAndPackets() {
  fetchPackets();

  fetch('/api/packets')
    .then(res => res.json())
    .then(data => {
      globalPacketData = data;
      dynamicProtocolCounts = {};

      data.forEach(pkt => {
        const proto = pkt.proto.toUpperCase();
        if (!dynamicProtocolCounts[proto]) {
          dynamicProtocolCounts[proto] = 0;
        }
        dynamicProtocolCounts[proto]++;
      });

      const dynamicProtocols = Object.keys(dynamicProtocolCounts);
      const dynamicCounts = Object.values(dynamicProtocolCounts);
      const dynamicColors = dynamicProtocols.map((_, i) => {
        const colors = ['#2ecc71', '#3498db', '#e74c3c', '#f1c40f', '#9b59b6', '#1abc9c', '#e67e22'];
        return colors[i % colors.length];
      });

      protocolChart.data.labels = dynamicProtocols;
      protocolChart.data.datasets[0].data = dynamicCounts;
      protocolChart.data.datasets[0].backgroundColor = dynamicColors;
      protocolChart.update();

      Object.keys(dynamicProtocolCounts).forEach(proto => {
        if (!protocolHistory[proto]) {
          protocolHistory[proto] = [];
        }
        protocolHistory[proto].push(dynamicProtocolCounts[proto]);
        if (protocolHistory[proto].length > 20) {
          protocolHistory[proto].shift();
        }
      });

      Object.keys(protocolHistory).forEach(proto => {
        if (!dynamicProtocolCounts[proto]) {
          protocolHistory[proto].push(0);
          if (protocolHistory[proto].length > 20) {
            protocolHistory[proto].shift();
          }
        }
      });

      const colors = ['#2ecc71', '#3498db', '#e74c3c', '#f1c40f', '#9b59b6', '#1abc9c', '#e67e22'];
      const datasets = Object.keys(protocolHistory).map((proto, i) => ({
        label: proto,
        data: protocolHistory[proto],
        borderColor: colors[i % colors.length],
        backgroundColor: colors[i % colors.length] + '33',
        tension: 0.3
      }));

      const nowTime = new Date().toLocaleTimeString();
      timeLabels.push(nowTime);
      if (timeLabels.length > 20) {
        timeLabels.shift();
      }
      protocolOverTimeChart.data.labels = timeLabels;
      protocolOverTimeChart.data.datasets = datasets;
      protocolOverTimeChart.update();

      let portUsage = {};

      data.forEach(pkt => {
        const ports = [pkt.src_port, pkt.dst_port];
        ports.forEach(port => {
          if (port && !isNaN(port)) {
            portUsage[port] = (portUsage[port] || 0) + 1;
          }
        });
      });

      const sortedPorts = Object.entries(portUsage)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

      const topPorts = sortedPorts.map(([port]) => port);
      const topCounts = sortedPorts.map(([_, count]) => count);

      const backgroundColors = topPorts.map(port => {
        if (!portColors[port]) {
          const r = Math.floor(Math.random() * 255);
          const g = Math.floor(Math.random() * 255);
          const b = Math.floor(Math.random() * 255);
          portColors[port] = `rgba(${r}, ${g}, ${b}, 0.7)`;
        }
        return portColors[port];
      });

      commonPortsChart.data.labels = topPorts;
      commonPortsChart.data.datasets[0].data = topCounts;
      commonPortsChart.data.datasets[0].backgroundColor = backgroundColors;
      commonPortsChart.update();

      if (analyticsProtocolChart) {
        analyticsProtocolChart.data.labels = dynamicProtocols;
        analyticsProtocolChart.data.datasets[0].data = dynamicCounts;
        analyticsProtocolChart.data.datasets[0].backgroundColor = dynamicColors;
        analyticsProtocolChart.update();
      }

      if (analyticsTrafficChart) {
        analyticsTrafficChart.data.labels = timeLabels;
        analyticsTrafficChart.data.datasets = datasets;
        analyticsTrafficChart.update();
      }

      if (analyticsPortsChart) {
        analyticsPortsChart.data.labels = topPorts;
        analyticsPortsChart.data.datasets[0].data = topCounts;
        analyticsPortsChart.data.datasets[0].backgroundColor = backgroundColors;
        analyticsPortsChart.update();
      }
    })
    .catch(err => console.error('Error updating charts:', err));
}

function makeModalDraggable(modal) {
  if (!modal) return;
  
  let isDragging = false;
  let offsetX = 0;
  let offsetY = 0;
  
  const header = modal.querySelector('.modal-header') || modal;
  
  header.addEventListener('mousedown', (e) => {
    if (e.target.closest('.close-btn')) return;
    
    isDragging = true;
    offsetX = e.clientX - modal.getBoundingClientRect().left;
    offsetY = e.clientY - modal.getBoundingClientRect().top;
    modal.style.cursor = 'grabbing';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    
    modal.style.left = `${e.clientX - offsetX}px`;
    modal.style.top = `${e.clientY - offsetY}px`;
    modal.style.right = 'auto';
    modal.style.bottom = 'auto';
    modal.style.transform = 'none';
  });

  document.addEventListener('mouseup', () => {
    isDragging = false;
    modal.style.cursor = '';
  });
}

const toggleToolsBtn = document.getElementById('toggle-tools');
const toolsPanel = document.getElementById('tools-panel');
const timeToolBtn = document.getElementById('time-tool-btn');
const timeModal = document.getElementById('time-tool-modal');

if (toggleToolsBtn) {
  toggleToolsBtn.addEventListener('click', () => {
    if (toolsPanel) {
      toolsPanel.classList.toggle('hidden');
      toggleToolsBtn.innerHTML = toolsPanel.classList.contains('hidden') ? 
        '<i class="fas fa-chevron-down"></i> Show Tools' : 
        '<i class="fas fa-chevron-up"></i> Hide Tools';
    }
  });
}

if (timeToolBtn) {
  timeToolBtn.addEventListener('click', () => {
    if (timeModal) {
      timeModal.classList.remove('hidden');
    }
  });
}

document.getElementById('close-time-modal')?.addEventListener('click', () => {
  document.getElementById('time-tool-modal')?.classList.add('hidden');
});

const timeModeSelect = document.getElementById('modal-position-select');
const exactTimeContainer = document.getElementById('exact-time-container');
const rangeTimeContainer = document.getElementById('range-time-container');

if (timeModeSelect) {
  timeModeSelect.addEventListener('change', (e) => {
    const selectedMode = e.target.value;
    if (selectedMode === 'exact') {
      exactTimeContainer?.classList.remove('hidden');
      rangeTimeContainer?.classList.add('hidden');
    } else if (selectedMode === 'range') {
      exactTimeContainer?.classList.add('hidden');
      rangeTimeContainer?.classList.remove('hidden');
    }
  });
}

makeModalDraggable(timeModal);

const portToolBtn = document.getElementById("port-tool-btn");
const portToolModal = document.getElementById("port-tool-modal");
const closePortModal = document.getElementById("close-port-modal");
const scanPortsBtn = document.getElementById("scan-ports-btn");
const portResults = document.getElementById("port-results");
let autoScanEnabled = false;
let autoScanIntervalId = null;
const autoScanToggle = document.getElementById("auto-scan-toggle");
let lastScannedIndex = 0;

if (autoScanToggle) {
  autoScanToggle.addEventListener("change", () => {
    autoScanEnabled = autoScanToggle.checked;
    if (autoScanEnabled) {
      startAutoScan();
    } else {
      stopAutoScan();
    }
  });
}

function startAutoScan() {
  autoScanIntervalId = setInterval(() => {
    runPortScan({ silent: true, source: "auto" });
  }, 10000);
}

function stopAutoScan() {
  clearInterval(autoScanIntervalId);
  autoScanIntervalId = null;
}

if (scanPortsBtn) {
  scanPortsBtn.addEventListener("click", () => {
    runPortScan({ silent: false });
  });
}

const knownDangerousPorts = [
  "21", "23", "25", "135", "139", "445", "1433", "3306", "3389", "5900", "6667", "8080"
];

if (portToolBtn) {
  portToolBtn.addEventListener("click", () => {
    if (portToolModal) portToolModal.classList.remove("hidden");
  });
}

if (closePortModal) {
  closePortModal.addEventListener("click", () => {
    if (portToolModal) portToolModal.classList.add("hidden");
  });
}

let portScanTimeoutId = null;
const alertBox = document.getElementById("port-alert");
const alertSound = document.getElementById("alert-sound");

function performPortScanLogic(silent = false, source = "manual") {
  if (alertBox) alertBox.classList.add("hidden");
  alertSound.pause();
  alertSound.currentTime = 0;

  const input = document.getElementById("custom-ports")?.value || "";
  const userPorts = input.split(',').map(p => p.trim()).filter(p => p !== "");
  const allPorts = [...new Set([...knownDangerousPorts, ...userPorts])];
  const filteredData = applyFilters(globalPacketData);
  let matches = [];

  const packetsToCheck = source === "auto" ? filteredData.slice(lastScannedIndex) : filteredData;

  for (let i = packetsToCheck.length - 1; i >= 0; i--) {
    const packet = packetsToCheck[i];
    const srcDetail = `${packet.src}:${packet.src_port}`;
    const dstDetail = `${packet.dst}:${packet.dst_port}`;
    const proto = (packet.proto || "Unknown").toLowerCase();

    for (const port of allPorts) {
      if (String(packet.src_port) === port || String(packet.dst_port) === port) {
        const match = `<li>${srcDetail} → ${dstDetail} (Protocol: ${proto}, Port: ${port})</li>`;
        matches.push(match);

        addTimelineEvent('Port Scan', 'medium', `Suspicious port ${port} activity`, packet.src, packet.dst, 'Heuristic');

        if (source === "auto") break;
      }
    }
    if (source === "auto" && matches.length) break;
  }

  if (source === "auto") lastScannedIndex = filteredData.length;

  if (!silent && source === "manual" && portResults) {
    portResults.innerHTML = matches.length ? `<ul>${matches.join("")}</ul>` : "<p>No suspicious ports found.</p>";
  }

  if (matches.length) {
    if (alertBox) alertBox.classList.remove("hidden");
    alertSound.play().catch(err => console.warn("Audio play failed:", err));
    if (source === "auto") {
      const autoScanResults = document.getElementById("auto-scan-results");
      if (autoScanResults) autoScanResults.innerHTML = `<ul>${matches.join("")}</ul>`;
    }
    setTimeout(() => {
      if (alertBox) alertBox.classList.add("hidden");
    }, 6000);
  }
}

const loadingOverlay = document.getElementById("global-loading-overlay");

function runPortScan({ silent = false, source = "manual" }) {
  if (!silent && loadingOverlay) {
    loadingOverlay.classList.remove("hidden");
    setTimeout(() => {
      const delay = Math.floor(Math.random() * (20000 - 5000 + 1)) + 5000;
      portScanTimeoutId = setTimeout(() => {
        performPortScanLogic(silent, source);
        if (loadingOverlay) loadingOverlay.classList.add("hidden");
        portScanTimeoutId = null;
      }, delay);
    }, 50);
  } else {
    performPortScanLogic(silent, source);
  }
}

document.getElementById("cancel-port-scan")?.addEventListener("click", () => {
  if (portScanTimeoutId) {
    clearTimeout(portScanTimeoutId);
    portScanTimeoutId = null;
  }
  document.getElementById("port-loading-overlay")?.classList.add("hidden");
  if (portResults) portResults.innerHTML = "<p>Scan cancelled by user.</p>";
});

function exportToCSV(data) {
  if (!data.length) return;
  
  const orderedHeaders = ['time', 'src', 'src_port', 'dst', 'dst_port', 'proto'];
  const csvRows = [orderedHeaders.join(',')];

  data.forEach(row => {
    const values = orderedHeaders.map(header => {
      const val = row[header] === null || row[header] === undefined ? '' : row[header];
      return `"${String(val).replace(/"/g, '""')}"`;
    });
    csvRows.push(values.join(','));
  });

  const csvContent = csvRows.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'packets_export.csv';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

document.getElementById('export-btn')?.addEventListener('click', () => {
  const filteredData = applyFilters(globalPacketData);
  exportToCSV(filteredData);
});

makeModalDraggable(portToolModal);

const blacklistToolBtn = document.getElementById("blacklist-tool-btn");
const blacklistModal = document.getElementById("blacklist-tool-modal");
const closeBlacklistModal = document.getElementById("close-blacklist-modal");
const runBlacklistScan = document.getElementById("run-blacklist-scan");
const blacklistResults = document.getElementById("blacklist-results");
let scanCancelled = false;
let autoBlacklistScanEnabled = false;
let autoBlacklistScanIntervalId = null;
let lastBlacklistScannedIndex = null;
let blacklistAlertQueue = [];
let isShowingAlert = false;
let blacklistScanDirection = "oldest";

if (blacklistToolBtn) {
  blacklistToolBtn.addEventListener("click", () => {
    if (blacklistModal) blacklistModal.classList.remove("hidden");
  });
}

if (closeBlacklistModal) {
  closeBlacklistModal.addEventListener("click", () => {
    if (blacklistModal) blacklistModal.classList.add("hidden");
  });
}

function fetchTotalPacketCount() {
  fetch('/api/packet_count')
    .then(response => response.json())
    .then(data => {
      document.getElementById('total-captured').textContent = data.total;
    });
}

setInterval(fetchTotalPacketCount, 2000);

function sendBlockedIPsToBackend() {
  const ipsToBlock = Array.from(blockedIPs);
  fetch('/api/block_ips', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips: ipsToBlock })
  })
  .then(response => response.json())
  .then(data => console.log("✅ Sent to backend:", data.blocked))
  .catch(error => console.error("❌ Error sending blocked IPs:", error));
}

function sendUnblockedIPsToBackend() {
  const ipsToUnblock = Array.from(blockedIPs);
  fetch('/api/unblock_ips', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips: ipsToUnblock })
  })
  .then(response => response.json())
  .then(data => console.log("✅ Unblocked on backend:", data.blocked))
  .catch(error => console.error("❌ Error unblocking IPs:", error));
}

function startAutoBlacklistScan() {
  autoBlacklistScanIntervalId = setInterval(() => {
    runBlacklistAutoScan();
  }, 10000);
}

function stopAutoBlacklistScan() {
  if (autoBlacklistScanIntervalId !== null) {
    clearInterval(autoBlacklistScanIntervalId);
    autoBlacklistScanIntervalId = null;
  }
  autoBlacklistScanEnabled = false;
  blacklistAlertQueue = [];
  isShowingAlert = false;
  const alertBoxElem = document.getElementById("blacklist-alert-box");
  if (alertBoxElem && !alertBoxElem.classList.contains("hidden")) {
    alertBoxElem.classList.add("fade-out");
    setTimeout(() => {
      alertBoxElem.classList.remove("fade-out");
      alertBoxElem.classList.add("hidden");
    }, 600);
  }
  const resultsBox = document.getElementById("blacklist-results");
  if (resultsBox) resultsBox.innerHTML = "";
}

if (runBlacklistScan) {
  runBlacklistScan.addEventListener("click", () => {
    scanCancelled = false;
    const fileInput = document.getElementById("blacklist-file");
    const manualInput = document.getElementById("manual-blacklist-input")?.value || "";
    if (loadingOverlay) loadingOverlay.classList.remove("hidden");
    setTimeout(() => {
      if (fileInput && fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = (e) => {
          const fileText = e.target.result;
          const blacklist = parseBlacklist(fileText, manualInput);
          scanAgainstBlacklist(blacklist);
          if (loadingOverlay) loadingOverlay.classList.add("hidden");
        };
        reader.readAsText(file);
      } else {
        const blacklist = parseBlacklist("", manualInput);
        scanAgainstBlacklist(blacklist);
        if (loadingOverlay) loadingOverlay.classList.add("hidden");
      }
    }, Math.random() * 1500 + 500);
  });
}

function parseBlacklist(fileContent, manualInput) {
  const combined = `${fileContent}\n${manualInput}`;
  const lines = combined.split(/\n/);
  const ips = lines.flatMap(line => {
    const columns = line.split(',').map(col => col.trim());
    const firstColumn = columns[0];
    return isValidIP(firstColumn) ? [firstColumn] : [];
  });
  return new Set(ips);
}

function isValidIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

const alertBlacklistBox = document.getElementById("blacklist-alert-box");
const alertBlacklistSound = document.getElementById("alert-sound");

function scanAgainstBlacklist(blacklistSet) {
  if (scanCancelled) return;
  const filteredData = applyFilters(globalPacketData);
  const hits = [];
  if (alertBlacklistBox) alertBlacklistBox.innerText = "";
  if (alertBlacklistBox) alertBlacklistBox.classList.add("hidden");
  for (const packet of filteredData) {
    if (scanCancelled) return;
    if (blacklistSet.has(packet.src) || blacklistSet.has(packet.dst)) {
      hits.push(`<li>${packet.time} – ${packet.src} → ${packet.dst} (${packet.proto})</li>`);
      
      const confidence = 95;
      incrementStat('blacklist')

     const evidence = {
          blacklistType: 'file',  
          sourceIP: packet.src,
          destinationIP: packet.dst,
          mitre: null  
      };

      addTimelineEvent(
          'Blacklist Hit',
          'high',
          `IP matched blacklist`,
          packet.src, packet.dst,
          {},
          confidence,
          'BlackList',
          null,
          evidence

            );
          }
        }

  if (!scanCancelled) {
    if (hits.length && alertBlacklistBox) {
      alertBlacklistBox.innerText = `⚠ Blacklist Match Found`;
      alertBlacklistBox.classList.remove("hidden");
      alertBlacklistSound.pause();
      alertBlacklistSound.currentTime = 0;
      alertBlacklistSound.play().catch(err => console.warn("Audio play failed:", err));
      setTimeout(() => {
        if (alertBlacklistBox) alertBlacklistBox.classList.add("hidden");
      }, 6000);
    }
    if (blacklistResults) {
      blacklistResults.innerHTML = hits.length ? `<ul>${hits.join("")}</ul>` : "<p>No matches found.</p>";
    }
  }
}

const cancelScanBtn = document.getElementById("cancel-port-scan");
if (cancelScanBtn) {
  cancelScanBtn.addEventListener("click", () => {
    scanCancelled = true;
    if (loadingOverlay) loadingOverlay.classList.add("hidden");
    if (blacklistResults) blacklistResults.innerHTML = "<p>Scan cancelled by user.</p>";
  });
}

const fileInput = document.getElementById("blacklist-file");
const fileNameDisplay = document.getElementById("blacklist-file-name");
if (fileInput) {
  fileInput.addEventListener("change", () => {
    if (fileNameDisplay) {
      if (fileInput.files.length > 0) {
        fileNameDisplay.textContent = `✔ File loaded: ${fileInput.files[0].name}`;
        fileNameDisplay.style.color = "#00ff99";
      } else {
        fileNameDisplay.textContent = "No file selected";
        fileNameDisplay.style.color = "#ccc";
      }
    }
  });
}

makeModalDraggable(blacklistModal);

function runBlacklistAutoScan() {
  if (!autoBlacklistScanEnabled) return;
  const fileInputElem = document.getElementById("blacklist-file");
  const manualInput = document.getElementById("manual-blacklist-input")?.value || "";
  if (fileInputElem && fileInputElem.files.length > 0) {
    const file = fileInputElem.files[0];
    const reader = new FileReader();
    reader.onload = (e) => {
      if (!autoBlacklistScanEnabled) return;
      const fileText = e.target.result;
      const blacklist = parseBlacklist(fileText, manualInput);
      scanAgainstBlacklistAuto(blacklist);
    };
    reader.readAsText(file);
  } else {
    if (!autoBlacklistScanEnabled) return;
    const blacklist = parseBlacklist("", manualInput);
    scanAgainstBlacklistAuto(blacklist);
  }
}

function scanAgainstBlacklistAuto(blacklistSet) {
  const filteredData = applyFilters(globalPacketData);
  if (!autoBlacklistScanEnabled) return;
  let packetsToCheck = [];
  if (blacklistScanDirection === "oldest") {
    packetsToCheck = filteredData.slice(lastBlacklistScannedIndex || 0);
    lastBlacklistScannedIndex = filteredData.length;
  } else if (blacklistScanDirection === "latest") {
    packetsToCheck = filteredData.slice().reverse();
    lastBlacklistScannedIndex = filteredData.length;
  } else if (blacklistScanDirection === "latest-forward") {
    if (lastBlacklistScannedIndex == null) {
      lastBlacklistScannedIndex = filteredData.length;
      return;
    }
    if (lastBlacklistScannedIndex >= filteredData.length) return;
    packetsToCheck = filteredData.slice(lastBlacklistScannedIndex);
    lastBlacklistScannedIndex = filteredData.length;
  }
  for (const packet of packetsToCheck) {
    if (!autoBlacklistScanEnabled) break;
    if (blacklistSet.has(packet.src) || blacklistSet.has(packet.dst)) {
      const detail = `${packet.time} – ${packet.src} → ${packet.dst} (${packet.proto})`;
      blacklistAlertQueue.push(detail);

      addTimelineEvent('Blacklist Hit', 'high', `IP matched blacklist (auto)`, packet.src, packet.dst, {}, 95, 'Blacklist');
    }
  }
  processNextBlacklistAlert();
}

function processNextBlacklistAlert() {
  if (isShowingAlert || blacklistAlertQueue.length === 0) return;
  isShowingAlert = true;
  const detail = blacklistAlertQueue.shift();
  showBlacklistAlert(detail);
  setTimeout(() => {
    isShowingAlert = false;
    processNextBlacklistAlert();
  }, 6000);
}

const optionsToggle = document.getElementById("options-toggle");
const optionsMenu = document.getElementById("blacklist-options-menu");
const optionItems = document.querySelectorAll(".option-item");

if (optionsToggle) {
  optionsToggle.addEventListener("click", () => {
    if (optionsMenu) optionsMenu.classList.toggle("hidden");
  });
}

optionItems.forEach(item => {
  item.addEventListener("click", () => {
    item.classList.toggle("active");
    const optionType = item.dataset.option;
    switch (optionType) {
      case "auto-scan":
        autoBlacklistScanEnabled = item.classList.contains("active");
        autoBlacklistScanEnabled ? startAutoBlacklistScan() : stopAutoBlacklistScan();
        break;
      case "block":
        const isBlocking = item.classList.contains("active");
        if (isBlocking) {
          const fileInputElem = document.getElementById("blacklist-file");
          const manualInput = document.getElementById("manual-blacklist-input")?.value || "";
          if (fileInputElem && fileInputElem.files.length > 0) {
            const reader = new FileReader();
            reader.onload = (e) => {
              const fileText = e.target.result;
              const blacklist = parseBlacklist(fileText, manualInput);
              blacklist.forEach(ip => blockedIPs.add(ip));
              sendBlockedIPsToBackend();
              fetchPackets();
            };
            reader.readAsText(fileInputElem.files[0]);
          } else {
            const blacklist = parseBlacklist("", manualInput);
            blacklist.forEach(ip => blockedIPs.add(ip));
            sendBlockedIPsToBackend();
            fetchPackets();
          }
        } else {
          sendUnblockedIPsToBackend();
          blockedIPs.clear();
          fetchPackets();
        }
        break;
    }
  });
});

function showBlacklistAlert(detail) {
  if (alertBlacklistBox) {
    alertBlacklistBox.classList.remove("hidden");
    alertBlacklistBox.innerText = `⚠ Blacklist Match Found: ${detail}`;
  }
  alertBlacklistSound.pause();
  alertBlacklistSound.currentTime = 0;
  alertBlacklistSound.play().catch(err => console.warn("Audio play failed:", err));
  const autoResults = document.getElementById("blacklist-results");
  if (autoResults) {
    let ul = autoResults.querySelector("ul");
    if (!ul) {
      ul = document.createElement("ul");
      autoResults.innerHTML = "";
      autoResults.appendChild(ul);
    }
    const li = document.createElement("li");
    li.innerText = detail;
    ul.appendChild(li);
  }
  setTimeout(() => {
    if (alertBlacklistBox) alertBlacklistBox.classList.add("hidden");
  }, 6000);
}

const submenuParent = document.querySelector(".with-submenu");
const submenu = submenuParent?.querySelector(".submenu");
let submenuTimeout;

if (submenuParent) {
  submenuParent.addEventListener("mouseenter", () => {
    clearTimeout(submenuTimeout);
    if (submenu) submenu.style.display = "block";
  });
  submenuParent.addEventListener("mouseleave", () => {
    submenuTimeout = setTimeout(() => {
      if (submenu) submenu.style.display = "none";
    }, 200);
  });
}
if (submenu) {
  submenu.addEventListener("mouseenter", () => {
    clearTimeout(submenuTimeout);
  });
  submenu.addEventListener("mouseleave", () => {
    submenuTimeout = setTimeout(() => {
      submenu.style.display = "none";
    }, 200);
  });
}

document.querySelectorAll(".submenu-item").forEach(item => {
  item.addEventListener("click", () => {
    document.querySelectorAll(".submenu-item").forEach(i => i.classList.remove("active"));
    item.classList.add("active");
    blacklistScanDirection = item.dataset.scanDir;
    if (blacklistScanDirection === "latest-forward") {
      lastBlacklistScannedIndex = globalPacketData.length;
    } else if (blacklistScanDirection === "latest") {
      lastBlacklistScannedIndex = 0;
    } else {
      lastBlacklistScannedIndex = 0;
    }
    console.log(`📍 Scan direction set to: ${blacklistScanDirection}`);
  });
});

const signatureToolBtn = document.getElementById("signature-tool-btn");
const signatureModal = document.getElementById("signature-modal");
const closeSignatureModal = document.getElementById("close-signature-modal");
const addSignatureBtn = document.getElementById("add-signature-btn");
const signatureInput = document.getElementById("signature-input");
const signatureList = document.getElementById("signature-list");
const startSignatureScan = document.getElementById("start-signature-scan");
const clearSignatureScan = document.getElementById("clear-signature-scan");
const signatureAlertBox = document.getElementById("signature-alert-box");
const signatureAlertSound = document.getElementById("alert-sound");
const signatureResults = document.getElementById("signature-results");
const globalLoadingOverlay = document.getElementById("global-loading-overlay");

let signatureAutoScanInterval = null;
let lastSignatureScannedIndex = null;
let signatureScanDirection = "oldest";
const signatureAlertQueue = [];
let isShowingSignatureAlert = false;
let signaturePatterns = [];
let signatureScanRunning = false;
let autoSignatureScanEnabled = false;
let signatureBlockingEnabled = false;

if (signatureToolBtn) {
  signatureToolBtn.addEventListener("click", () => {
    if (signatureModal) signatureModal.classList.remove("hidden");
  });
}

if (closeSignatureModal) {
  closeSignatureModal.addEventListener("click", () => {
    if (signatureModal) signatureModal.classList.add("hidden");
  });
}

function sendBlockedSignaturesToBackend() {
  const patternStrings = signaturePatterns.map(p => p.source);
  fetch('/api/block_signatures', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ patterns: patternStrings })
  })
  .then(res => res.json())
  .then(data => console.log("✅ Backend blocking these signatures:", data.blocked_signatures));
}

function sendUnblockedSignaturesToBackend() {
  fetch('/api/unblock_signatures', {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  })
  .then(res => res.json())
  .then(data => console.log("✅ Signature blocking disabled:", data));
}

if (addSignatureBtn) {
  addSignatureBtn.addEventListener("click", () => {
    const pattern = signatureInput?.value.trim();
    if (pattern && signatureList) {
      signaturePatterns.push(new RegExp(pattern, "i"));
      const li = document.createElement("li");
      li.textContent = pattern;
      signatureList.appendChild(li);
      if (signatureInput) signatureInput.value = "";
    }
  });
}

if (startSignatureScan) {
  startSignatureScan.addEventListener("click", () => {
    signatureScanRunning = true;
    if (globalLoadingOverlay) globalLoadingOverlay.classList.remove("hidden");
    if (signatureResults) signatureResults.innerHTML = "";
    const scanDelay = Math.floor(Math.random() * 15000) + 5000;
    setTimeout(() => {
      if (signatureScanRunning) {
        scanForSignatures();
      }
    }, scanDelay);
  });
}

function scanForSignatures() {
  const filteredData = applyFilters(globalPacketData);
  const sortedData = filteredData.slice().sort((a, b) => new Date(b.time) - new Date(a.time));
  const hits = [];
  for (const packet of sortedData) {
    if (!signatureScanRunning) return;
    const payload = packet.payload || packet.raw || packet.content || "";
    for (const pattern of signaturePatterns) {
      if (pattern.test(payload)) {
        const detail = `${packet.time} – ${packet.src} → ${packet.dst} (${packet.proto})`;
        hits.push(`<li>${detail} – Matched: <code>${pattern}</code></li>`);
        
        const confidence = (severity === 'critical') ? 90 : 70;
        incrementStat('signature')
        addTimelineEvent('Signature Match', 'high', `Pattern: ${pattern.source} matched`, packet.src, packet.dst, { pattern: pattern.source },
    confidence, 'Signature');

        if (signatureAlertBox) signatureAlertBox.classList.remove("hidden");
        signatureAlertSound.pause();
        signatureAlertSound.currentTime = 0;
        signatureAlertSound.play().catch(err => console.warn("Sound play failed:", err));
        setTimeout(() => {
          if (signatureAlertBox) signatureAlertBox.classList.add("hidden");
        }, 6000);
        break;
      }
    }
  }
  if (globalLoadingOverlay) globalLoadingOverlay.classList.add("hidden");
  if (signatureResults) {
    signatureResults.innerHTML = hits.length ? `<ul>${hits.join("")}</ul>` : "<p>No matches found.</p>";
  }
}

function startAutoSignatureScanLoop() {
  if (signatureAutoScanInterval) clearInterval(signatureAutoScanInterval);
  signatureAutoScanInterval = setInterval(() => {
    if (!autoSignatureScanEnabled) return;
    runSignatureAutoScan();
  }, 20000);
}

function stopAutoSignatureScanLoop() {
  if (signatureAutoScanInterval) {
    clearInterval(signatureAutoScanInterval);
    signatureAutoScanInterval = null;
  }
}

function stopAutoSignatureScan() {
  autoSignatureScanEnabled = false;
  stopAutoSignatureScanLoop();
  signatureAlertQueue.length = 0;
  isShowingSignatureAlert = false;
  if (signatureAlertBox && !signatureAlertBox.classList.contains("hidden")) {
    signatureAlertBox.classList.add("fade-out");
    setTimeout(() => {
      signatureAlertBox.classList.remove("fade-out");
      signatureAlertBox.classList.add("hidden");
      if (signatureAlertBox) signatureAlertBox.innerHTML = "";
    }, 600);
  }
}

function runSignatureAutoScan() {
  if (!autoSignatureScanEnabled || signaturePatterns.length === 0) return;
  const filteredData = applyFilters(globalPacketData);
  let packetsToCheck = [];
  if (signatureScanDirection === "oldest") {
    packetsToCheck = filteredData.slice(lastSignatureScannedIndex || 0);
    lastSignatureScannedIndex = filteredData.length;
  } else if (signatureScanDirection === "latest") {
    packetsToCheck = filteredData.slice().reverse();
    lastSignatureScannedIndex = filteredData.length;
  } else if (signatureScanDirection === "latest-forward") {
    if (lastSignatureScannedIndex == null) {
      lastSignatureScannedIndex = filteredData.length;
      return;
    }
    if (lastSignatureScannedIndex >= filteredData.length) return;
    packetsToCheck = filteredData.slice(lastSignatureScannedIndex);
    lastSignatureScannedIndex = filteredData.length;
  }
  scanAgainstSignatureAuto(packetsToCheck);
}

function scanAgainstSignatureAuto(packetsToCheck) {
  if (!autoSignatureScanEnabled || !packetsToCheck?.length) return;
  for (const packet of packetsToCheck) {
    if (!autoSignatureScanEnabled) break;
    const payload = packet.payload || packet.raw || packet.content || "";
    for (const pattern of signaturePatterns) {
      if (pattern.test(payload)) {
        const detail = `${packet.time} – ${packet.src} → ${packet.dst} (${packet.proto}) Matched: ${pattern}`;
        signatureAlertQueue.push(detail);
        break;
      }
    }
  }
  processNextSignatureAlert();
}

function processNextSignatureAlert() {
  if (isShowingSignatureAlert || signatureAlertQueue.length === 0) return;
  isShowingSignatureAlert = true;
  const detail = signatureAlertQueue.shift();
  showSignatureAlert(detail);
  setTimeout(() => {
    isShowingSignatureAlert = false;
    processNextSignatureAlert();
  }, 6000);
}

function showSignatureAlert(detail) {
  if (signatureAlertBox) {
    signatureAlertBox.innerHTML = `<p>${detail}</p>`;
    signatureAlertBox.classList.remove("hidden");
  }
  signatureAlertSound.pause();
  signatureAlertSound.currentTime = 0;
  signatureAlertSound.play().catch(err => console.warn("Sound play failed:", err));
  const autoResults = document.getElementById("signature-results");
  if (autoResults) {
    let ul = autoResults.querySelector("ul");
    if (!ul) {
      ul = document.createElement("ul");
      autoResults.innerHTML = "";
      autoResults.appendChild(ul);
    }
    const li = document.createElement("li");
    li.innerText = detail;
    ul.appendChild(li);
  }
  setTimeout(() => {
    if (signatureAlertBox) signatureAlertBox.classList.add("hidden");
  }, 5000);
}

if (cancelScanBtn) {
  cancelScanBtn.addEventListener("click", () => {
    scanCancelled = true;
    if (loadingOverlay) loadingOverlay.classList.add("hidden");
    if (signatureResults) signatureResults.innerHTML = "<p>Scan cancelled by user.</p>";
  });
}

if (clearSignatureScan) {
  clearSignatureScan.addEventListener("click", () => {
    signaturePatterns = [];
    if (signatureList) signatureList.innerHTML = "";
    if (signatureInput) signatureInput.value = "";
    if (signatureResults) signatureResults.innerHTML = "";
  });
}

makeModalDraggable(signatureModal);

const signatureOptionsToggleBtn = document.getElementById("signature-options-toggle");
const signatureOptionsMenuElem = document.getElementById("signature-options-menu");
const signatureOptionItemsList = document.querySelectorAll(".signature-option-item");

if (signatureOptionsToggleBtn) {
  signatureOptionsToggleBtn.addEventListener("click", () => {
    if (signatureOptionsMenuElem) signatureOptionsMenuElem.classList.toggle("hidden");
  });
}

signatureOptionItemsList.forEach(item => {
  item.addEventListener("click", () => {
    const optionType = item.dataset.option;
    item.classList.toggle("active");
    const isActive = item.classList.contains("active");
    if (optionType === "auto-scan") {
      autoSignatureScanEnabled = isActive;
      if (isActive) {
        startAutoSignatureScanLoop();
      } else {
        stopAutoSignatureScan();
      }
    }
    if (optionType === "block") {
      signatureBlockingEnabled = isActive;
      if (isActive) {
        const patternStrings = signaturePatterns.map(p => p.source);
        sendBlockedSignaturesToBackend();
        globalPacketData = globalPacketData.filter(packet => {
          const payload = packet.payload || packet.raw || packet.content || "";
          return !signaturePatterns.some(p => p.test(payload));
        });
        renderPackets(applyFilters(globalPacketData));
      } else {
        sendUnblockedSignaturesToBackend();
        fetchPackets();
      }
    }
  });
});

const signatureSubmenuItemsList = document.querySelectorAll(".signature-submenu-item");
signatureSubmenuItemsList.forEach(item => {
  item.addEventListener("click", (e) => {
    e.stopPropagation();
    signatureSubmenuItemsList.forEach(i => i.classList.remove("active"));
    item.classList.add("active");
    signatureScanDirection = item.dataset.scanDir;
  });
});

const signatureSubmenuParentElem = document.querySelector("#signature-options-menu .with-submenu");
const signatureSubmenuElem = signatureSubmenuParentElem?.querySelector(".signature-submenu");
let signatureSubmenuTimeout;

if (signatureSubmenuParentElem) {
  signatureSubmenuParentElem.addEventListener("mouseenter", () => {
    clearTimeout(signatureSubmenuTimeout);
    if (signatureSubmenuElem) signatureSubmenuElem.style.display = "block";
  });
  signatureSubmenuParentElem.addEventListener("mouseleave", () => {
    signatureSubmenuTimeout = setTimeout(() => {
      if (signatureSubmenuElem) signatureSubmenuElem.style.display = "none";
    }, 200);
  });
}
if (signatureSubmenuElem) {
  signatureSubmenuElem.addEventListener("mouseenter", () => {
    clearTimeout(signatureSubmenuTimeout);
  });
  signatureSubmenuElem.addEventListener("mouseleave", () => {
    signatureSubmenuTimeout = setTimeout(() => {
      if (signatureSubmenuElem) signatureSubmenuElem.style.display = "none";
    }, 200);
  });
}

const manipulateBtn = document.getElementById("manipulate-tool-btn");
const manipulateModalElem = document.getElementById("manipulate-tool-modal");
const closeManipulateBtn = document.getElementById("close-manipulate-modal");
const packetIndexSelectElem = document.getElementById("packetIndex");
const applyEditsBtnElem = document.getElementById("apply-packet-edits");

if (manipulateBtn) {
  manipulateBtn.addEventListener("click", () => {
    isEditingPacket = true;
    populatePacketOptions();
    if (manipulateModalElem) manipulateModalElem.classList.remove("hidden");
  });
}

if (closeManipulateBtn) {
  closeManipulateBtn.addEventListener("click", () => {
    if (manipulateModalElem) manipulateModalElem.classList.add("hidden");
  });
}

function populatePacketOptions() {
  if (packetIndexSelectElem) {
    packetIndexSelectElem.innerHTML = '';
    globalPacketData.forEach((packet, i) => {
      const opt = document.createElement("option");
      opt.value = i;
      opt.textContent = `${i + 1} | ${packet.src} -> ${packet.dst}`;
      packetIndexSelectElem.appendChild(opt);
    });
    loadPacketIntoForm(0);
  }
}

if (packetIndexSelectElem) {
  packetIndexSelectElem.addEventListener("change", () => {
    loadPacketIntoForm(packetIndexSelectElem.value);
  });
}

function loadPacketIntoForm(index) {
  const pkt = globalPacketData[index];
  if (!pkt) return;
  const editSrc = document.getElementById("editSrc");
  const editDst = document.getElementById("editDst");
  const editProto = document.getElementById("editProto");
  const editSrcPort = document.getElementById("editSrcPort");
  const editDstPort = document.getElementById("editDstPort");
  const editPayload = document.getElementById("editPayload");
  if (editSrc) editSrc.value = pkt.src || '';
  if (editDst) editDst.value = pkt.dst || '';
  if (editProto) editProto.value = pkt.proto || '';
  if (editSrcPort) editSrcPort.value = pkt.src_port || '';
  if (editDstPort) editDstPort.value = pkt.dst_port || '';
  if (editPayload) editPayload.value = pkt.payload || '';
}

if (applyEditsBtnElem) {
  applyEditsBtnElem.addEventListener("click", () => {
    if (!selectedPacketId) {
      console.error("❌ No selectedPacketId during apply");
      return;
    }
    const pkt = globalPacketData.find(p => p.id === selectedPacketId);
    if (!pkt) {
      console.error("❌ Packet not found for ID", selectedPacketId);
      return;
    }
    const editSrc = document.getElementById("editSrc");
    const editDst = document.getElementById("editDst");
    const editProto = document.getElementById("editProto");
    const editSrcPort = document.getElementById("editSrcPort");
    const editDstPort = document.getElementById("editDstPort");
    const editPayload = document.getElementById("editPayload");
    if (editSrc) pkt.src = editSrc.value;
    if (editDst) pkt.dst = editDst.value;
    if (editProto) pkt.proto = editProto.value;
    if (editSrcPort) pkt.src_port = Number(editSrcPort.value);
    if (editDstPort) pkt.dst_port = Number(editDstPort.value);
    if (editPayload) pkt.payload = editPayload.value;
    renderPackets(applyFilters(globalPacketData));
    if (manipulateModalElem) manipulateModalElem.classList.add("hidden");
    isEditingPacket = false;
    const successBox = document.getElementById("manipulate-success-box");
    if (successBox) {
      successBox.classList.remove("hidden");
      successBox.classList.add("show");
      setTimeout(() => {
        successBox.classList.remove("show");
        setTimeout(() => successBox.classList.add("hidden"), 400);
      }, 3000);
    }
  });
}

makeModalDraggable(manipulateModalElem);

function openManipulateModalById(packetId) {
  const pkt = globalPacketData.find(p => p.id === packetId);
  if (!pkt) {
    console.error("❌ Packet not found for modal:", packetId);
    return;
  }
  const editSrc = document.getElementById("editSrc");
  const editDst = document.getElementById("editDst");
  const editProto = document.getElementById("editProto");
  const editSrcPort = document.getElementById("editSrcPort");
  const editDstPort = document.getElementById("editDstPort");
  const editPayload = document.getElementById("editPayload");
  if (editSrc) editSrc.value = pkt.src || '';
  if (editDst) editDst.value = pkt.dst || '';
  if (editProto) editProto.value = pkt.proto || '';
  if (editSrcPort) editSrcPort.value = pkt.src_port || '';
  if (editDstPort) editDstPort.value = pkt.dst_port || '';
  if (editPayload) editPayload.value = pkt.payload || '';
  if (manipulateModalElem) manipulateModalElem.classList.remove("hidden");
}

function updateFlowAnalysisTable() {
  const tbody = document.querySelector('#flow-analysis-table tbody');
  if (!tbody) return;
  
  const flows = new Map();
  
  globalPacketData.forEach(packet => {
    const flowKey = `${packet.src}:${packet.src_port || 'any'}→${packet.dst}:${packet.dst_port || 'any'}`;
    if (!flows.has(flowKey)) {
      flows.set(flowKey, {
        id: flowKey.substring(0, 40),
        source: `${packet.src}:${packet.src_port || 'any'}`,
        destination: `${packet.dst}:${packet.dst_port || 'any'}`,
        protocol: packet.proto,
        packets: 0,
        riskScore: 0,
        status: 'OK'
      });
    }
    const flow = flows.get(flowKey);
    flow.packets++;
    flow.riskScore = Math.min(flow.riskScore + (packet.host_score || 0), 100);
    if (flow.riskScore >= 50) flow.status = 'ALERT';
    if (flow.riskScore >= 80) flow.status = 'BLOCK';
  });
  
  tbody.innerHTML = '';
  const flowsArray = Array.from(flows.values()).slice(0, 50);
  const flowsAnalysedElem = document.getElementById('flows-analysed');
  if (flowsAnalysedElem) flowsAnalysedElem.textContent = flowsArray.length;
  
  if (flowsArray.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No flow data yet. Capture some packets first.</td></tr>';
    return;
  }
  
  flowsArray.forEach(flow => {
    const row = document.createElement('tr');
    let statusClass = '';
    if (flow.status === 'ALERT') statusClass = 'host-alert';
    if (flow.status === 'BLOCK') statusClass = 'host-block';
    
    const sourceIP = flow.source.split(':')[0]; 
    const destIP = flow.destination.split(':')[0];

    row.innerHTML = `
        <td><code title="${flow.id}">${flow.id.substring(0, 35)}${flow.id.length > 35 ? '...' : ''}</code></td>
        <td><span class="ip-intel-trigger" data-ip="${sourceIP}">${flow.source}</span></td>
        <td><span class="ip-intel-trigger" data-ip="${destIP}">${flow.destination}</span></td>
        <td>${flow.protocol}</td>
        <td style="text-align: center;">${flow.packets}</td>
        <td style="text-align: center;">${flow.riskScore.toFixed(1)}</td>
        <td class="${statusClass}" style="text-align: center;">${flow.status}</td>
    `;
    tbody.appendChild(row);
  });
}

async function updateHostRiskChart() {
  const ctx = document.getElementById('hostRiskChart')?.getContext('2d');
  if (!ctx) return;
  
  try {
    const res = await fetch("/api/hosts");
    const data = await res.json();
    
    const hosts = Object.values(data);
    const hostNames = hosts.slice(0, 15).map(h => h.host);
    const riskScores = hosts.slice(0, 15).map(h => h.score);
    
    const activeHostsElem = document.getElementById('active-hosts');
    if (activeHostsElem) activeHostsElem.textContent = hosts.length;
    
    const alerts = hosts.filter(h => h.status === 'ALERT' || h.status === 'BLOCK').length;
    const alertsCountElem = document.getElementById('alerts-count');
    if (alertsCountElem) alertsCountElem.textContent = alerts;
    
    const packetsCapturedElem = document.getElementById('packets-captured');
    if (packetsCapturedElem) packetsCapturedElem.textContent = globalPacketData.length;
    
    if (hostRiskChart) {
      hostRiskChart.destroy();
    }
    
    hostRiskChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: hostNames.length ? hostNames : ['No Data'],
        datasets: [{
          label: 'Risk Score',
          data: riskScores.length ? riskScores : [0],
          backgroundColor: riskScores.length ? riskScores.map(score => {
            if (score >= 80) return '#ef4444';
            if (score >= 50) return '#f59e0b';
            return '#10b981';
          }) : ['#6b7280'],
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { labels: { color: '#9ca3af' } }
        },
        scales: {
          y: {
            beginAtZero: true,
            max: 100,
            grid: { color: '#2a2a30' },
            ticks: { color: '#9ca3af' }
          },
          x: {
            ticks: { color: '#9ca3af', maxRotation: 45, minRotation: 45 },
            grid: { display: false }
          }
        }
      }
    });

  if (analyticsRiskChart) {
    analyticsRiskChart.data.labels = hostNames.length ? hostNames : ['No Data'];
    analyticsRiskChart.data.datasets[0].data = riskScores.length ? riskScores : [0];
    analyticsRiskChart.data.datasets[0].backgroundColor = riskScores.length ? riskScores.map(score => {
      if (score >= 80) return '#ef4444';
      if (score >= 50) return '#f59e0b';
      return '#10b981';
    }) : ['#6b7280'];
    analyticsRiskChart.update();
  }
  } catch (error) {
    console.error("Error updating host risk chart:", error);
  }
}

async function refreshHostRisk() {
  try {
    const res = await fetch("/api/hosts");
    const data = await res.json();
    mlInfoMap.clear();
        Object.values(data).forEach(h => {
            mlInfoMap.set(h.host, {
                label: h.label,
                confidence: h.confidence,
                score: h.score,
                status: h.status
            });
        });
    const tbody = document.querySelector("#host-risk-table tbody");
    if (tbody) {
      tbody.innerHTML = "";
      Object.values(data).forEach(h => {
        const oldStatus = hostPreviousStatus.get(h.host);
        if (oldStatus && oldStatus !== h.status) {
          let severity = 'medium';
          if (h.status === 'BLOCK') severity = 'critical';
          else if (h.status === 'ALERT') severity = 'high';
          incrementStat('hostRisk')
          const confidence = 60;

         const evidence = {
          oldStatus: oldStatus,
          newStatus: h.status,
          score: h.score,
          host: h.host
      };
      addTimelineEvent(
          'Host Risk Change',
          severity,
          `Host ${h.host} status changed from ${oldStatus} to ${h.status} (score ${h.score})`,
          h.host, null,
          { oldStatus, newStatus: h.status, score: h.score },
          confidence,
          'ML',
          null,
          evidence
      );
        }

        const asset = getAssetByIdentifier(h.host);
        if (!asset) {
            createOrUpdateAsset(h.host, {
                hostname: h.host,
                owner: 'Unknown',
                risk: h.score,
                status: h.status === 'OK' ? 'Healthy' : h.status === 'ALERT' ? 'Under Investigation' : 'Blocked',
                alerts: 0,
                criticality: 'Medium',
                os: 'Unknown',
                tags: []
            });
        } else {
            
            if (asset.risk !== h.score) {
                asset.risk = h.score;
                asset.riskHistory.push({ timestamp: Date.now(), score: h.score });
                if (asset.riskHistory.length > 100) asset.riskHistory.shift();
            }
            const newStatus = h.status === 'OK' ? 'Healthy' : h.status === 'ALERT' ? 'Under Investigation' : 'Blocked';
            if (asset.status !== newStatus) asset.status = newStatus;
            asset.lastSeen = Date.now();
            saveAssets();
        }

        hostPreviousStatus.set(h.host, h.status);
        const row = document.createElement("tr");
        let statusClass = "host-ok";
        if (h.status === "ALERT") statusClass = "host-alert";
        if (h.status === "BLOCK") statusClass = "host-block";
        row.innerHTML = `
            <td><span class="ip-intel-trigger" data-ip="${h.host}">${h.host}</span></td>
            <td class="${statusClass}">${h.status}</td>
            <td>${h.score.toFixed(2)}</td>
            <td>${h.label}</td>
            <td>${(h.confidence * 100).toFixed(1)}%</td>
            <td>
                <button class="killchain-btn btn-secondary" data-host="${h.host}" title="View ATT&CK Kill Chain">
                    <i class="fas fa-crosshairs"></i> View
                </button>
            </td>
        `;
        tbody.appendChild(row);
      });
    }
    const threatTbody = document.querySelector('#threat-host-table tbody');
    if (threatTbody) threatTbody.innerHTML = tbody ? tbody.innerHTML : '';
    await updateHostRiskChart();
    updateFlowAnalysisTable();
    updateHostRiskHeatmap();
  } catch (error) {
    console.error("Error refreshing host risk:", error);
  }
}

document.addEventListener('click', function(e) {
    const btn = e.target.closest('.killchain-btn');
    if (!btn) return;
    const host = btn.dataset.host;
    if (host) {
        showKillChain(host);
    }
});

function openAssetDetail(assetId) {
    const asset = assets.find(a => a.id === parseInt(assetId));
    if (!asset) {
        showToast('Asset not found.', 'danger');
        return;
    }
    const modal = document.getElementById('asset-detail-modal');
    const title = document.getElementById('asset-detail-title');
    const content = document.getElementById('asset-detail-content');
    title.textContent = `Asset: ${asset.hostname} (${asset.ip})`;

    
    const alerts = timelineEvents.filter(e => e.src === asset.ip || e.dst === asset.ip);
    const iocMatches = iocs.filter(ioc => ioc.hits && ioc.hits.some(h => h.src === asset.ip || h.dst === asset.ip));
    const casesRelated = cases.filter(c => {
        if (c.alerts) {
            return c.alerts.some(alertId => alerts.some(a => a.id === alertId));
        }
        return false;
    });
    
    const techs = {};
    alerts.forEach(a => {
        if (a.mitre) {
            techs[a.mitre] = (techs[a.mitre] || 0) + 1;
        }
    });

    
    let html = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;">
            <div><strong>IP:</strong> ${asset.ip}</div>
            <div><strong>Hostname:</strong> ${asset.hostname}</div>
            <div><strong>Owner:</strong> ${asset.owner}</div>
            <div><strong>Risk:</strong> <span style="color:${asset.risk>=80?'#ef4444':asset.risk>=50?'#f59e0b':'#10b981'}">${asset.risk.toFixed(1)}</span></div>
            <div><strong>Criticality:</strong> <span class="severity-${asset.criticality.toLowerCase()}">${asset.criticality}</span></div>
            <div><strong>OS:</strong> ${asset.os}</div>
            <div><strong>Tags:</strong> ${(asset.tags||[]).map(t=>`<span class="asset-tag">${t}</span>`).join(' ') || '—'}</div>
            <div><strong>Status:</strong> <span class="status-badge ${asset.status==='Blocked'?'host-block':asset.status==='Under Investigation'?'host-alert':'host-ok'}">${asset.status}</span></div>
            <div><strong>Alerts:</strong> ${asset.alerts}</div>
            <div><strong>First Seen:</strong> ${asset.createdAt ? new Date(asset.createdAt).toLocaleString() : '—'}</div>
            <div><strong>Last Seen:</strong> ${asset.lastSeen ? new Date(asset.lastSeen).toLocaleString() : '—'}</div>
        </div>
        <div><strong>Risk History</strong></div>
        <canvas id="asset-detail-spark" height="60" style="width:100%;"></canvas>
        <hr style="border-color:var(--border); margin:16px 0;">
        <div><strong>MITRE Techniques</strong></div>
        <div>${Object.keys(techs).length ? Object.entries(techs).map(([t,c]) => `<span class="mitre-badge">${t} (${c})</span>`).join(' ') : 'None'}</div>
        <hr style="border-color:var(--border); margin:16px 0;">
        <div><strong>Related Alerts (${alerts.length})</strong></div>
        <div style="max-height:150px; overflow-y:auto;">
            ${alerts.slice(0,20).forEach(a => {
            html += `<div style="cursor:pointer;" onclick="openAlertInvestigation('${a.id}')">${formatAlertTime(a)} - ${a.eventType} (${a.severity})</div>`;
        })}}
        </div>
        <hr style="border-color:var(--border); margin:16px 0;">
        <div><strong>Related IOCs (${iocMatches.length})</strong></div>
        <div>${iocMatches.map(i => `<span class="ioc-type-badge">${i.value}</span>`).join(' ') || 'None'}</div>
        <hr style="border-color:var(--border); margin:16px 0;">
        <div><strong>Related Cases (${casesRelated.length})</strong></div>
        <div>${casesRelated.map(c => `<span class="priority-badge">#${c.id} ${c.title}</span>`).join(' ') || 'None'}</div>
    `;
    content.innerHTML = html;
    modal.classList.remove('hidden');

    
    setTimeout(() => {
        const ctx = document.getElementById('asset-detail-spark')?.getContext('2d');
        if (ctx) {
            const history = asset.riskHistory || [];
            const labels = history.map(h => new Date(h.timestamp).toLocaleDateString());
            const data = history.map(h => h.score);
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        borderColor: '#6366f1',
                        borderWidth: 2,
                        fill: true,
                        backgroundColor: 'rgba(99,102,241,0.1)',
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true, max: 100 } }
                }
            });
        }
    }, 100);
}

document.getElementById('close-asset-detail')?.addEventListener('click', () => {
    document.getElementById('asset-detail-modal').classList.add('hidden');
});

function renderAssetsTable() {
    const tbody = document.getElementById('assets-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;">No assets discovered yet. Assets are auto-created from host risk data.</td></tr>';
        return;
    }
    const sorted = assets.slice().sort((a, b) => b.risk - a.risk);
    sorted.forEach(asset => {
        const row = document.createElement('tr');
        const statusClass = asset.status === 'Blocked' ? 'host-block' : asset.status === 'Under Investigation' ? 'host-alert' : 'host-ok';
        const criticalityBadge = `<span class="severity-${asset.criticality.toLowerCase()}">${asset.criticality}</span>`;
        const tagsHtml = (asset.tags || []).map(t => `<span class="asset-tag">${t}</span>`).join(' ');
        const firstSeen = asset.createdAt ? new Date(asset.createdAt).toLocaleDateString() : '—';
        
        const sparkId = `spark-${asset.id}`;
        row.innerHTML = `
            <td><span class="ip-intel-trigger" data-ip="${asset.ip}">${asset.ip}</span></td>
            <td>${asset.hostname}</td>
            <td>${asset.owner}</td>
            <td style="font-weight:600; color: ${asset.risk >= 80 ? '#ef4444' : asset.risk >= 50 ? '#f59e0b' : '#10b981'}">${asset.risk.toFixed(1)}</td>
            <td>${criticalityBadge}</td>
            <td>${asset.os}</td>
            <td>${tagsHtml}</td>
            <td>${asset.alerts}</td>
            <td><span class="status-badge ${statusClass}">${asset.status}</span></td>
            <td>${firstSeen}</td>
            <td><canvas id="${sparkId}" class="sparkline-container" width="80" height="25"></canvas></td>
            <td>
                <div class="asset-actions-dropdown">
                    <button class="pivot-btn asset-actions-btn" data-id="${asset.id}"><i class="fas fa-ellipsis-v"></i></button>
                    <div class="asset-actions-dropdown-content" data-id="${asset.id}">
                        <a data-action="detail" data-id="${asset.id}">📋 Detail</a>
                        <a data-action="timeline" data-ip="${asset.ip}">⏳ Timeline</a>
                        <a data-action="graph" data-ip="${asset.ip}">🌐 Graph</a>
                        <a data-action="hunt" data-ip="${asset.ip}">🔍 Hunt</a>
                        <a data-action="cases" data-ip="${asset.ip}">📁 Cases</a>
                        <a data-action="alerts" data-ip="${asset.ip}">🚨 Alerts</a>
                    </div>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });

    
    document.querySelectorAll('.asset-actions-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            const content = document.querySelector(`.asset-actions-dropdown-content[data-id="${id}"]`);
            if (content) {
                content.classList.toggle('show');
            }
        });
    });

    
    document.querySelectorAll('.asset-actions-dropdown-content a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.stopPropagation();
            const action = this.dataset.action;
            const id = this.dataset.id;
            const ip = this.dataset.ip;
            
            this.closest('.asset-actions-dropdown-content').classList.remove('show');
            switch (action) {
                case 'detail': openAssetDetail(id); break;
                case 'timeline': viewTimelineForNode(ip); break;
                case 'graph': switchView('investigation'); break;
                case 'hunt': {
                    document.getElementById('hunting-query-input').value = `src:${ip} OR dst:${ip}`;
                    switchView('hunting');
                    document.getElementById('hunting-run-btn').click();
                    break;
                }
                case 'cases': {
                    switchView('cases');
                    const caseSearch = document.getElementById('case-search') || document.getElementById('alert-search');
                    if (caseSearch) caseSearch.value = ip;
                    renderCasesTable();
                    break;
                }
                case 'alerts': {
                    switchView('alerts');
                    document.getElementById('alert-search').value = ip;
                    renderAlertsTable();
                    break;
                }
            }
        });
    });

    
    document.addEventListener('click', function() {
        document.querySelectorAll('.asset-actions-dropdown-content.show').forEach(el => el.classList.remove('show'));
    });

setTimeout(() => {
    sorted.forEach(asset => {
        const chartId = `spark-${asset.id}`;
        const canvas = document.getElementById(chartId);
        if (canvas) {
            
            if (sparklineCharts[chartId]) {
                sparklineCharts[chartId].destroy();
                delete sparklineCharts[chartId];
            }
            const ctx = canvas.getContext('2d');
            const history = asset.riskHistory || [];
            const labels = history.map(h => new Date(h.timestamp).toLocaleDateString());
            const data = history.map(h => h.score);
            sparklineCharts[chartId] = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        borderColor: '#6366f1',
                        borderWidth: 1.5,
                        pointRadius: 0,
                        tension: 0.2,
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
                    animation: { duration: 0 }
                }
            });
        }
    });
  }, 100);
}



function confidenceColor(score) {
    if (score >= 80) return '#10b981';
    if (score >= 60) return '#fbbf24';
    if (score >= 40) return '#f59e0b';
    return '#ef4444';
}

const backdrop = document.getElementById('modal-backdrop');
function showBackdrop() { backdrop?.classList.remove('hidden'); }
function hideBackdrop() { backdrop?.classList.add('hidden'); }
document.querySelectorAll('.modal').forEach(modal => {
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      if (mutation.attributeName === 'class') {
        if (!modal.classList.contains('hidden')) showBackdrop();
        else hideBackdrop();
      }
    });
  });
  observer.observe(modal, { attributes: true });
});
backdrop?.addEventListener('click', () => {
  document.querySelectorAll('.modal:not(.hidden)').forEach(modal => modal.classList.add('hidden'));
  hideBackdrop();
});



function updateStatsCards(data) {
  const packetsCapturedElem = document.getElementById('packets-captured');
  if (packetsCapturedElem) packetsCapturedElem.textContent = data.length || 0;
  
  const avgRisk = data.reduce((sum, p) => sum + (p.host_score || 0), 0) / (data.length || 1);
  const avgRiskElem = document.getElementById('avg-risk');
  if (avgRiskElem) avgRiskElem.textContent = avgRisk.toFixed(1);
}

let startTime = Date.now();
setInterval(() => {
  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  const hours = Math.floor(elapsed / 3600);
  const seconds = elapsed % 60;
  const uptimeElem = document.getElementById('uptime');
  if (uptimeElem) {
  }
}, 1000);

const clearFiltersBtn = document.getElementById('clear-filters');
if (clearFiltersBtn) {
  clearFiltersBtn.addEventListener('click', () => {
    const protocolFilter = document.getElementById('protocolFilter');
    const srcFilter = document.getElementById('srcFilter');
    const dstFilter = document.getElementById('dstFilter');
    const srcPortFilter = document.getElementById('srcPortFilter');
    const dstPortFilter = document.getElementById('dstPortFilter');
    const payloadFilter = document.getElementById('payloadFilter');
    const exactTimeInput = document.getElementById('exactTime');
    const startTimeInput = document.getElementById('startTime');
    const endTimeInput = document.getElementById('endTime');
    if (protocolFilter) protocolFilter.value = '';
    if (srcFilter) srcFilter.value = '';
    if (dstFilter) dstFilter.value = '';
    if (srcPortFilter) srcPortFilter.value = '';
    if (dstPortFilter) dstPortFilter.value = '';
    if (payloadFilter) payloadFilter.value = '';
    if (exactTimeInput) exactTimeInput.value = '';
    if (startTimeInput) startTimeInput.value = '';
    if (endTimeInput) endTimeInput.value = '';
    renderPackets(applyFilters(globalPacketData));
  });
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    item.classList.add('active');
    const view = item.dataset.view;
    if (view === 'packets') {
      document.querySelector('.packets-section')?.scrollIntoView({ behavior: 'smooth' });
    } else if (view === 'threats') {
      document.querySelector('.ml-dashboard')?.scrollIntoView({ behavior: 'smooth' });
    } else if (view === 'analytics') {
      document.querySelector('.charts-section')?.scrollIntoView({ behavior: 'smooth' });
    } else if (view === 'flows') {
      document.querySelector('.flow-analysis-section')?.scrollIntoView({ behavior: 'smooth' });
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  });
});

const originalFetchPackets = fetchPackets;
fetchPackets = function() {
  originalFetchPackets();
  fetch('/api/packets')
    .then(res => res.json())
    .then(data => {
      updateStatsCards(data);
      updateFlowAnalysisTable();
    })
    .catch(err => console.error(err));
};

function isPrivateIP(ip) {
    const octets = ip.split('.').map(Number);
    return (
        ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
        ip === '127.0.0.1'
    );
}

function getFlagEmoji(countryCode) {
    if (countryCode === 'LOC') return '🏠';
    if (countryCode === 'UNK') return '🌍';
    const codePoints = [...countryCode.toUpperCase()].map(c => 127397 + c.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

const geoCache = new Map();

async function getCountryFromIp(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip);

  const octets = ip.split('.').map(Number);
  const isLocal = ip.startsWith('192.168.') || ip.startsWith('10.') ||
                  (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
                  ip === '127.0.0.1';
  if (isLocal) {
    const result = { code: 'LOC', name: 'Local Network', flag: '🏠', city: 'Local', lat: null, lon: null };
    geoCache.set(ip, result);
    enforceCacheLimit();  
    return result;
  }

  try {
    const response = await fetch(`/api/geo/${ip}`);
    const data = await response.json();

    if (data.country_code) {
      const result = {
        code: data.country_code,
        name: data.country_name,
        flag: getFlagEmoji(data.country_code),
        city: data.city || data.country_name,
        lat: data.latitude,
        lon: data.longitude
      };
      geoCache.set(ip, result);
      enforceCacheLimit();
      return result;
    } else {
      throw new Error('Invalid response');
    }
  } catch (error) {
    console.warn(`Geo lookup failed for ${ip}:`, error);
    const fallback = { code: 'UNK', name: 'Unknown', flag: '🌍', city: 'Unknown', lat: null, lon: null };
    geoCache.set(ip, fallback);
    enforceCacheLimit();
    return fallback;
  }
}

function enforceCacheLimit() {
    const MAX_CACHE_SIZE = 10000;
    if (geoCache.size > MAX_CACHE_SIZE) {
        const toDelete = Math.floor(geoCache.size * 0.2);
        const keys = [...geoCache.keys()];
        for (let i = 0; i < toDelete; i++) {
            geoCache.delete(keys[i]);
        }
    }
}


let sourceCountryMap = new Map(); 
let destCountryMap = new Map();
let countryRiskMap = new Map();  
let flowLines = new Map();    

async function updateGeoStats() {
    if (isUpdatingGeo) return;
    isUpdatingGeo = true;

    const heatmapContainer = document.getElementById('heatmap-grid');

    try {
        sourceCountryMap.clear();
        destCountryMap.clear();

        if (heatmapContainer && globalPacketData.length > 0) {
            heatmapContainer.innerHTML = '<div class="heatmap-placeholder">🌍 Loading geo data...</div>';
        }

        if (globalPacketData.length === 0) {
            if (heatmapContainer) {
                heatmapContainer.innerHTML = '<div class="heatmap-placeholder">No geo data yet. Capture some packets.</div>';
            }
            safeSetText('unique-src-countries', '0');
            safeSetText('unique-dst-countries', '0');
            const srcTbody = document.querySelector('#source-country-table tbody');
            if (srcTbody) srcTbody.innerHTML = '<tr><td colspan="3">No source data</td></tr>';
            const dstTbody = document.querySelector('#dest-country-table tbody');
            if (dstTbody) dstTbody.innerHTML = '<tr><td colspan="3">No destination data</td></tr>';
            const threatTbody = document.querySelector('#threat-countries-table tbody');
            if (threatTbody) threatTbody.innerHTML = '<tr><td colspan="3">No threat data</td></tr>';
            document.getElementById('geo-success-rate').textContent = 'Geo Success: N/A';
            return;
        }

        
        const uniqueIPs = [...new Set(globalPacketData.flatMap(pkt => [pkt.src, pkt.dst]))];
        const uncachedIPs = uniqueIPs.filter(ip => !geoCache.has(ip));
        const BATCH_SIZE = 25;
        for (let i = 0; i < uncachedIPs.length; i += BATCH_SIZE) {
            const batch = uncachedIPs.slice(i, i + BATCH_SIZE);
            await Promise.all(batch.map(ip => getCountryFromIp(ip)));
        }

        
        const hostRiskMap = new Map();
        try {
            const riskRes = await fetch('/api/hosts');
            const riskData = await riskRes.json();
            for (const [host, info] of Object.entries(riskData)) {
                hostRiskMap.set(host, info.score);
            }
        } catch (e) {
            console.warn('Could not fetch host risk data');
        }

        
        for (const pkt of globalPacketData) {
            const srcCountry = geoCache.get(pkt.src);
            const dstCountry = geoCache.get(pkt.dst);
            if (srcCountry) {
                if (!sourceCountryMap.has(srcCountry.code)) {
                    sourceCountryMap.set(srcCountry.code, {
                        name: srcCountry.name,
                        count: 0,
                        flag: srcCountry.flag
                    });
                }
                sourceCountryMap.get(srcCountry.code).count++;
            }
            if (dstCountry) {
                if (!destCountryMap.has(dstCountry.code)) {
                    destCountryMap.set(dstCountry.code, {
                        name: dstCountry.name,
                        count: 0,
                        flag: dstCountry.flag
                    });
                }
                destCountryMap.get(dstCountry.code).count++;
            }
        }

        
        const ipCoordMap = new Map();
        flowLines.clear();
        const ipPacketCount = new Map();

        for (const pkt of globalPacketData) {
            const srcGeo = geoCache.get(pkt.src);
            const dstGeo = geoCache.get(pkt.dst);

            ipPacketCount.set(pkt.src, (ipPacketCount.get(pkt.src) || 0) + 1);
            ipPacketCount.set(pkt.dst, (ipPacketCount.get(pkt.dst) || 0) + 1);

            if (srcGeo && srcGeo.lat !== null && srcGeo.lon !== null) {
                ipCoordMap.set(pkt.src, {
                    lat: srcGeo.lat, lon: srcGeo.lon,
                    city: srcGeo.city, name: srcGeo.name
                });
            }
            if (dstGeo && dstGeo.lat !== null && dstGeo.lon !== null) {
                ipCoordMap.set(pkt.dst, {
                    lat: dstGeo.lat, lon: dstGeo.lon,
                    city: dstGeo.city, name: dstGeo.name
                });
            }

            const key = `${pkt.src}→${pkt.dst}`;
            if (!flowLines.has(key)) {
                flowLines.set(key, { src: pkt.src, dst: pkt.dst, count: 0, riskSum: 0 });
            }
            const f = flowLines.get(key);
            f.count++;

            
            const srcRisk = hostRiskMap.get(pkt.src) || 0;
            const dstRisk = hostRiskMap.get(pkt.dst) || 0;
            const flowRisk = Math.max(srcRisk, dstRisk);
            f.riskSum += flowRisk;
        }

        
        const localFallback = { lat: 51.4490, lon: -0.4450, city: 'Local (Office)', name: 'Local Network' };
        for (const ip of uniqueIPs) {
            if (isPrivateIP(ip) && !ipCoordMap.has(ip)) {
                ipCoordMap.set(ip, localFallback);
            }
        }

        
        let totalPublic = 0, totalResolved = 0;
        for (const ip of uniqueIPs) {
            if (isPrivateIP(ip)) continue;
            totalPublic++;
            const geo = geoCache.get(ip);
            if (geo && geo.lat !== null && geo.lon !== null) totalResolved++;
        }
        const successRate = totalPublic ? ((totalResolved / totalPublic) * 100).toFixed(1) : 100;
        document.getElementById('geo-success-rate').textContent = `Geo Success: ${successRate}%`;

        
        if (!window.geoMap) {
            window.geoMap = L.map('world-map').setView([20, 0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; CartoDB',
                subdomains: 'abcd',
                maxZoom: 19,
                minZoom: 1
            }).addTo(window.geoMap);
        }
        if (!window.markerGroup) window.markerGroup = L.layerGroup().addTo(window.geoMap);
        if (!window.lineGroup) window.lineGroup = L.layerGroup().addTo(window.geoMap);
        window.markerGroup.clearLayers();
        window.lineGroup.clearLayers();

        
        for (let [ip, coord] of ipCoordMap.entries()) {
            const hostRisk = hostRiskMap.get(ip);
            const hasHostRisk = hostRisk !== undefined;

            
            let totalFlowRisk = 0, flowCount = 0;
            for (const [_, flow] of flowLines.entries()) {
                if (flow.src === ip || flow.dst === ip) {
                    totalFlowRisk += (flow.riskSum / flow.count);
                    flowCount++;
                }
            }
            const avgFlowRisk = flowCount > 0 ? (totalFlowRisk / flowCount) : null;

            const displayRisk = hasHostRisk ? hostRisk.toFixed(1) : (avgFlowRisk !== null ? avgFlowRisk.toFixed(1) : 'Unknown');
            const effectiveRisk = hasHostRisk ? hostRisk : (avgFlowRisk !== null ? avgFlowRisk : 0);
            const packetCount = ipPacketCount.get(ip) || 1;
            const radius = Math.min(15, 4 + Math.log(packetCount) * 2);

            let markerColor = '#10b981';
            if (effectiveRisk > 80) markerColor = '#ef4444';
            else if (effectiveRisk > 50) markerColor = '#f59e0b';
            else if (effectiveRisk > 25) markerColor = '#fbbf24';
            else if (effectiveRisk > 0 && !hasHostRisk) markerColor = '#6b7280';
            if (!hasHostRisk && avgFlowRisk === null) markerColor = '#6b7280';

            const marker = L.circleMarker([coord.lat, coord.lon], {
                radius: radius,
                color: markerColor,
                fillColor: markerColor,
                fillOpacity: 0.8,
                weight: 1
            }).addTo(window.markerGroup);
            marker.bindPopup(`
                <b>${ip}</b><br>
                📍 ${coord.city || coord.name}<br>
                🌍 ${coord.name}<br>
                🛡️ Risk: ${displayRisk}<br>
                📦 Packets: ${packetCount}
            `);
        }
        
        const flowsTableBody = document.querySelector('#geo-flows-table tbody');
        if (flowsTableBody) {
            const sortedFlows = Array.from(flowLines.values())
                .sort((a, b) => (b.riskSum / b.count) - (a.riskSum / a.count))
                .slice(0, 10);
            flowsTableBody.innerHTML = sortedFlows.map(flow => {
                const avgRisk = (flow.riskSum / flow.count).toFixed(1);
                const riskClass = avgRisk > 80 ? 'host-block' : (avgRisk > 50 ? 'host-alert' : 'host-ok');
                return `
                    <tr>
                        <td><span class="flag">${getFlagEmojiFromIp(flow.src)}</span> <span class="ip-intel-trigger" data-ip="${flow.src}">${flow.src}</span></td>
                        <td><span class="flag">${getFlagEmojiFromIp(flow.dst)}</span> <span class="ip-intel-trigger" data-ip="${flow.dst}">${flow.dst}</span></td>
                        <td>${flow.count}</td>
                        <td class="${riskClass}">${avgRisk}</td>
                    </tr>
                `;
            }).join('');
        }

        
        for (let [_, flow] of flowLines.entries()) {
            const srcCoord = ipCoordMap.get(flow.src);
            const dstCoord = ipCoordMap.get(flow.dst);
            if (!srcCoord || !dstCoord) continue;
            if (typeof srcCoord.lat !== 'number' || typeof srcCoord.lon !== 'number' ||
                typeof dstCoord.lat !== 'number' || typeof dstCoord.lon !== 'number') continue;

            const avgRisk = flow.riskSum / flow.count;
            const points = [[srcCoord.lat, srcCoord.lon], [dstCoord.lat, dstCoord.lon]];
            let color = '#10b981';
            if (avgRisk > 80) color = '#ef4444';
            else if (avgRisk > 50) color = '#f59e0b';
            else if (avgRisk > 25) color = '#fbbf24';

            const antPathFunc = L.polyline.antPath || L.Polyline.antPath;
            if (antPathFunc && typeof antPathFunc === 'function') {
                try {
                    const antPoly = antPathFunc(points, {
                        color: color,
                        weight: 3,
                        opacity: 0.8,
                        delay: 400,
                        dashArray: [10, 20],
                        pulseColor: '#ffffff'
                    }).addTo(window.lineGroup);
                    antPoly.bindTooltip(`${flow.src} → ${flow.dst}<br>Risk: ${avgRisk.toFixed(1)}<br>Packets: ${flow.count}`, { sticky: true });
                } catch (e) {
                    const polyline = L.polyline(points, { color: color, weight: 2, opacity: 0.5 }).addTo(window.lineGroup);
                    polyline.bindTooltip(`${flow.src} → ${flow.dst}<br>Risk: ${avgRisk.toFixed(1)}<br>Packets: ${flow.count}`, { sticky: true });
                }
            } else {
                const polyline = L.polyline(points, { color: color, weight: 2, opacity: 0.5 }).addTo(window.lineGroup);
                polyline.bindTooltip(`${flow.src} → ${flow.dst}<br>Risk: ${avgRisk.toFixed(1)}<br>Packets: ${flow.count}`, { sticky: true });
            }
        }

        
        document.getElementById('unique-src-countries').textContent = sourceCountryMap.size;
        document.getElementById('unique-dst-countries').textContent = destCountryMap.size;

        const combinedMap = new Map();
        for (let [code, data] of sourceCountryMap.entries()) {
            combinedMap.set(code, { ...data, total: data.count });
        }
        for (let [code, data] of destCountryMap.entries()) {
            if (combinedMap.has(code)) {
                combinedMap.get(code).total += data.count;
            } else {
                combinedMap.set(code, { ...data, total: data.count });
            }
        }

        const sortedCountries = Array.from(combinedMap.entries())
            .sort((a, b) => b[1].total - a[1].total)
            .slice(0, 24);

        if (heatmapContainer) {
            if (sortedCountries.length === 0) {
                heatmapContainer.innerHTML = '<div class="heatmap-placeholder">No geo data yet. Capture some packets.</div>';
            } else {
                const maxCount = sortedCountries[0][1].total;
                heatmapContainer.innerHTML = '';
                for (const [code, data] of sortedCountries) {
                    let intensity = 0;
                    if (maxCount > 0) {
                        const ratio = data.total / maxCount;
                        if (ratio > 0.75) intensity = 4;
                        else if (ratio > 0.5) intensity = 3;
                        else if (ratio > 0.25) intensity = 2;
                        else if (ratio > 0.05) intensity = 1;
                    }
                    const tile = document.createElement('div');
                    tile.className = 'heatmap-tile';
                    tile.setAttribute('data-intensity', intensity);
                    tile.setAttribute('title', `${data.name}: ${data.total} packets`);
                    tile.innerHTML = `
                        <span class="country-code">${data.flag || ''} ${code}</span>
                        <span class="country-name">${data.name}</span>
                        <div class="count">${data.total}</div>
                    `;
                    tile.addEventListener('click', () => showCountryDetails(code, data.name));
                    heatmapContainer.appendChild(tile);
                }
            }
        }

        const srcTbody = document.querySelector('#source-country-table tbody');
        if (srcTbody) {
            const totalSrcPackets = Array.from(sourceCountryMap.values()).reduce((sum, c) => sum + c.count, 0);
            const sortedSrc = Array.from(sourceCountryMap.entries())
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 10);
            srcTbody.innerHTML = sortedSrc.map(([code, data]) => {
                const percent = totalSrcPackets ? ((data.count / totalSrcPackets) * 100).toFixed(1) : 0;
                return `<tr><td>${data.flag || ''} ${data.name}</td><td>${data.count}</td><td>${percent}%</td></tr>`;
            }).join('');
            if (sortedSrc.length === 0) srcTbody.innerHTML = '<tr><td colspan="3">No source data</td></tr>';
        }

        const dstTbody = document.querySelector('#dest-country-table tbody');
        if (dstTbody) {
            const totalDstPackets = Array.from(destCountryMap.values()).reduce((sum, c) => sum + c.count, 0);
            const sortedDst = Array.from(destCountryMap.entries())
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 10);
            dstTbody.innerHTML = sortedDst.map(([code, data]) => {
                const percent = totalDstPackets ? ((data.count / totalDstPackets) * 100).toFixed(1) : 0;
                return `<tr><td>${data.flag || ''} ${data.name}</td><td>${data.count}</td><td>${percent}%</td></tr>`;
            }).join('');
            if (sortedDst.length === 0) dstTbody.innerHTML = '<tr><td colspan="3">No destination data</td></tr>';
        }

        
        countryRiskMap.clear();
        for (const pkt of globalPacketData) {
            const srcGeo = geoCache.get(pkt.src);
            const dstGeo = geoCache.get(pkt.dst);
            const srcRisk = hostRiskMap.get(pkt.src) || 0;
            const dstRisk = hostRiskMap.get(pkt.dst) || 0;

            
            const addCountryRisk = (geo, risk) => {
                if (!geo) return;
                let code = geo.code;
                let name = geo.name;
                let flag = geo.flag;
                if (code === 'LOC') {
                    code = 'LOCAL';
                    name = 'Local Network';
                    flag = '🏠';
                }
                if (!countryRiskMap.has(code)) {
                    countryRiskMap.set(code, { name, flag, sumRisk: 0, count: 0 });
                }
                const c = countryRiskMap.get(code);
                c.sumRisk += risk;
                c.count++;
            };

            addCountryRisk(srcGeo, srcRisk);
            addCountryRisk(dstGeo, dstRisk);
        }

        const threatTbody = document.querySelector('#threat-countries-table tbody');
        if (threatTbody) {
            const sortedThreats = Array.from(countryRiskMap.entries())
                .map(([code, data]) => ({
                    code,
                    name: data.name,
                    flag: data.flag,
                    avgRisk: data.count > 0 ? (data.sumRisk / data.count).toFixed(1) : 0,
                    packets: data.count
                }))
                .filter(c => c.avgRisk > 0)
                .sort((a, b) => b.avgRisk - a.avgRisk)
                .slice(0, 10);

            threatTbody.innerHTML = sortedThreats.map(c => {
                const riskNum = parseFloat(c.avgRisk);
                let badge = '';
                if (riskNum >= 80) badge = '<span class="threat-badge critical">Critical</span>';
                else if (riskNum >= 50) badge = '<span class="threat-badge high">High</span>';
                else if (riskNum >= 25) badge = '<span class="threat-badge medium">Medium</span>';
                else badge = '<span class="threat-badge low">Low</span>';
                const threatDisplay = `${badge} (${riskNum.toFixed(1)})`;
                return `
                    <tr>
                        <td>${c.flag || ''} ${c.name}</td>
                        <td>${threatDisplay}</td>
                        <td>${c.packets}</td>
                    </tr>
                `;
            }).join('');
            if (sortedThreats.length === 0) threatTbody.innerHTML = '<tr><td colspan="3">No threat data</td></tr>';
        }

        
        const uniqueCountries = new Set([
            ...sourceCountryMap.keys(),
            ...destCountryMap.keys()
        ]);
        const hostScores = [...hostRiskMap.values()];
        const avgRiskScore = hostScores.length
            ? hostScores.reduce((a, b) => a + b, 0) / hostScores.length
            : 0;

        updateGeoScorecard(
            uniqueCountries.size,
            Array.from(countryRiskMap.entries()).sort((a, b) => (b[1].sumRisk / b[1].count) - (a[1].sumRisk / a[1].count))[0]?.[1]?.name || 'None',
            avgRiskScore,
            parseFloat(successRate)
        );

        updateThreatPieChart(hostRiskMap);
        updateSourceBarChart();          
        updateRiskTimeline(hostRiskMap);
        updateCountryRiskHeatmap();       
        updateSankey();             

    } catch (error) {
        console.error('Error updating geo stats:', error);
        const heatmapContainer = document.getElementById('heatmap-grid');
        if (heatmapContainer) {
            heatmapContainer.innerHTML = '<div class="heatmap-placeholder">⚠️ Error loading geo data. Check console.</div>';
        }
    } finally {
        isUpdatingGeo = false;
    }
}

function getFlagEmojiFromIp(ip) {
    const cached = geoCache.get(ip);
    return cached ? cached.flag : '🌍';
}

function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'danger' ? 'fa-exclamation-triangle' : 'fa-info-circle'}"></i><span>${message}</span>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

window.showToast = showToast;

async function showCountryDetails(countryCode, countryName) {
    
    const packetsInCountry = globalPacketData.filter(pkt => {
        const src = geoCache.get(pkt.src);
        const dst = geoCache.get(pkt.dst);
        return (src && src.code === countryCode) || (dst && dst.code === countryCode);
    });
    
    
    const cityCounts = new Map();
    for (const pkt of packetsInCountry) {
        const src = geoCache.get(pkt.src);
        const dst = geoCache.get(pkt.dst);
        if (src && src.code === countryCode && src.city && src.city !== 'Local') {
            cityCounts.set(src.city, (cityCounts.get(src.city) || 0) + 1);
        }
        if (dst && dst.code === countryCode && dst.city && dst.city !== 'Local') {
            cityCounts.set(dst.city, (cityCounts.get(dst.city) || 0) + 1);
        }
    }
    
    const modal = document.getElementById('country-detail-modal');
    const title = document.getElementById('country-name-modal');
    const container = document.getElementById('country-cities-list');
    if (title) title.textContent = `${countryName} (${countryCode})`;
    if (container) {
        if (cityCounts.size === 0) {
            container.innerHTML = '<p>No city data available for this country.</p>';
        } else {
            container.innerHTML = '<ul>' + Array.from(cityCounts.entries())
                .sort((a,b) => b[1] - a[1])
                .map(([city, count]) => `<li><strong>${city}</strong>: ${count} packets</li>`)
                .join('') + '</ul>';
        }
    }
    if (modal) modal.classList.remove('hidden');
    }

const closeCountryModal = document.getElementById('close-country-modal');
if (closeCountryModal) {
    closeCountryModal.addEventListener('click', () => {
        document.getElementById('country-detail-modal').classList.add('hidden');
    });
}

function updateGeoScorecard(countriesCount, highestRiskCountry, avgRiskScore, resolutionRate) {
    safeSetText('geo-countries-seen', countriesCount);
    safeSetText('geo-highest-risk-country', highestRiskCountry);
    safeSetText('geo-avg-risk-score', avgRiskScore.toFixed(1));
    safeSetText('geo-resolution-rate', `${resolutionRate}%`);
}

function updateThreatPieChart(riskMap) {
    const buckets = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const pkt of globalPacketData) {
        const risk = riskMap.get(pkt.src) || riskMap.get(pkt.dst) || 0;
        if (risk >= 80) buckets.critical++;
        else if (risk >= 50) buckets.high++;
        else if (risk >= 25) buckets.medium++;
        else buckets.low++;
    }
    geoThreatChart.data.datasets[0].data = [buckets.critical, buckets.high, buckets.medium, buckets.low];
    geoThreatChart.update();
  }

function updateSourceBarChart() {
    const sorted = Array.from(sourceCountryMap.entries()).sort((a,b) => b[1].count - a[1].count).slice(0,10);
    geoSourceBarChart.data.labels = sorted.map(([_,d]) => d.name);
    geoSourceBarChart.data.datasets[0].data = sorted.map(([_,d]) => d.count);
    geoSourceBarChart.update();
}

function updateRiskTimeline(riskMap) {
    const timeBuckets = {};
    for (const pkt of globalPacketData) {
        if (!pkt.time) continue;
        const minute = pkt.time.slice(0, 5);
        if (!timeBuckets[minute]) timeBuckets[minute] = { riskSum: 0, count: 0 };
        const risk = riskMap.get(pkt.src) || riskMap.get(pkt.dst) || 0;
        timeBuckets[minute].riskSum += risk;
        timeBuckets[minute].count++;
    }
    const labels = Object.keys(timeBuckets).sort();
    const data = labels.map(t => timeBuckets[t].riskSum / timeBuckets[t].count);
    geoRiskTimeline.data.labels = labels;
    geoRiskTimeline.data.datasets[0].data = data;
    geoRiskTimeline.update();
}
function updateCountryRiskHeatmap() {
    const container = document.getElementById('risk-heatmap-grid');
    if (!container) return;
    const countries = Array.from(countryRiskMap.entries())
        .map(([code,data]) => ({ code, name: data.name, flag: data.flag, avgRisk: data.sumRisk / data.count }))
        .sort((a,b) => b.avgRisk - a.avgRisk)
        .slice(0,24);
    if (countries.length === 0) {
        container.innerHTML = '<div class="heatmap-placeholder">No risk data yet.</div>';
        return;
    }
    const maxRisk = countries[0].avgRisk;
    container.innerHTML = '';
    for (const c of countries) {
        let intensity = 0;
        const ratio = c.avgRisk / maxRisk;
        if (ratio > 0.75) intensity = 4;
        else if (ratio > 0.5) intensity = 3;
        else if (ratio > 0.25) intensity = 2;
        else if (ratio > 0.05) intensity = 1;
        const tile = document.createElement('div');
        tile.className = 'heatmap-tile';
        tile.setAttribute('data-intensity', intensity);
        tile.setAttribute('title', `${c.name}: Avg Risk ${c.avgRisk.toFixed(1)}`);
        tile.innerHTML = `<span class="country-code">${c.flag || ''} ${c.code}</span><span class="country-name">${c.name}</span><div class="count">${c.avgRisk.toFixed(1)}</div>`;
        tile.addEventListener('click', () => showCountryDetails(c.code, c.name));
        container.appendChild(tile);
    }
}
function updateSankey() {
    const countryPairs = new Map();
    for (const [_, flow] of flowLines.entries()) {
        const srcGeo = geoCache.get(flow.src);
        const dstGeo = geoCache.get(flow.dst);
        if (!srcGeo || !dstGeo) continue;

        const srcCode = srcGeo.code === 'LOC' ? 'LOCAL' : srcGeo.code;
        const dstCode = dstGeo.code === 'LOC' ? 'LOCAL' : dstGeo.code;
        const srcName = srcGeo.code === 'LOC' ? 'Local Network' : srcGeo.name;
        const dstName = dstGeo.code === 'LOC' ? 'Local Network' : dstGeo.name;

        const key = `${srcCode}→${dstCode}`;
        if (!countryPairs.has(key)) {
            countryPairs.set(key, {
                src: srcCode,
                dst: dstCode,
                srcName: srcName,
                dstName: dstName,
                count: 0,
                riskSum: 0
            });
        }
        const pair = countryPairs.get(key);
        pair.count += flow.count;
        pair.riskSum += flow.riskSum;
    }

    const topPairs = Array.from(countryPairs.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 15);

    const nodes = new Set();
    topPairs.forEach(p => { nodes.add(p.src); nodes.add(p.dst); });
    const nodeList = Array.from(nodes);
    const nodeIndex = {};
    nodeList.forEach((n, i) => nodeIndex[n] = i);

    const nodeNames = nodeList.map(code => {
        if (code === 'LOCAL') return 'Local Network';
        const geo = Array.from(geoCache.values()).find(g => g.code === code);
        return geo ? geo.name : code;
    });

    const links = topPairs.map(p => ({
        source: nodeIndex[p.src],
        target: nodeIndex[p.dst],
        value: p.count,
        customdata: [(p.riskSum / p.count).toFixed(1)],
        hovertemplate: '%{source.label} → %{target.label}<br>Packets: %{value}<br>Avg Risk: %{customdata}<extra></extra>'
    }));

    const sankeyData = [{
        type: 'sankey',
        orientation: 'horizontal',
        node: {
            label: nodeNames,
            pad: 15,
            thickness: 20,
            line: { color: '#2a2a30', width: 0.5 },
            color: '#6366f1'
        },
        link: {
            source: links.map(l => l.source),
            target: links.map(l => l.target),
            value: links.map(l => l.value),
            customdata: links.map(l => l.customdata),
            hovertemplate: links[0]?.hovertemplate || ''
        }
    }];
    const layout = {
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { color: '#ccc' },
        margin: { t: 30, l: 10, r: 10, b: 10 }
    };

    if (!sankeyInitialized) {
        Plotly.newPlot('sankey-container', sankeyData, layout);
        sankeyInitialized = true;
    } else {
        Plotly.react('sankey-container', sankeyData, layout);
    }
}

function safeSetText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}
function safeSetHTML(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

let pendingFpAlertId = null;

function showFpModal(alertId) {
    pendingFpAlertId = alertId;
    document.getElementById('fp-reason-input').value = '';
    document.getElementById('fp-modal').classList.remove('hidden');
}

function closeFpModal() {
    document.getElementById('fp-modal').classList.add('hidden');
    pendingFpAlertId = null;
}

document.getElementById('close-fp-modal')?.addEventListener('click', closeFpModal);
document.getElementById('fp-cancel-btn')?.addEventListener('click', closeFpModal);
document.getElementById('fp-modal')?.addEventListener('click', function(e) {
    if (e.target === this) closeFpModal();
});

document.getElementById('fp-confirm-btn')?.addEventListener('click', function() {
    const reason = document.getElementById('fp-reason-input').value.trim();
    if (!reason) {
        showToast('Please enter a reason.', 'warning');
        return;
    }
    if (pendingFpAlertId !== null) {
        updateAlertStatus(pendingFpAlertId, 'false_positive', reason);
        closeFpModal();
    }
});
function updateAlertStatus(alertId, newStatus, notes = '') {
    alertId = String(alertId);
    const alert = timelineEvents.find(e => String(e.id) === alertId);
    if (!alert) return;

    if (!alert.notes) alert.notes = [];
    if (!alert.investigationNotes) alert.investigationNotes = [];

    alert.status = newStatus;
    if (newStatus === 'investigating' && !alert.acknowledgedAt) {
        alert.acknowledgedAt = Date.now();
    }
    if (newStatus === 'resolved') {
        alert.resolvedAt = Date.now();
    }
    if (newStatus === 'false_positive' && notes) {
        alert.falsePositiveReason = notes;
    }
    if (notes) {
        alert.notes.push(notes);
    }

    renderTimeline();
    renderAlertsTable();
    updateAlertCounts();
    if (currentInvestigationAlertId === alertId) {
        refreshInvestigationModal();
    }
    updateAlertMetrics();

    alert = timelineEvents.find(e => e.id === alertId);
    if (alert && alert.incidentId) {
        const inc = incidents.find(i => i.id === alert.incidentId);
        if (inc) {
            const allTerminal = [...inc.alertIds].every(id => {
                const a = timelineEvents.find(e => e.id === id);
                return a && (a.status === 'resolved' || a.status === 'false_positive');
            });
            if (allTerminal && inc.status !== 'resolved' && inc.status !== 'false_positive') {
                inc.status = newStatus === 'false_positive' ? 'false_positive' : 'resolved';
                inc.resolvedAt = Date.now();
                inc.updatedAt = Date.now();
                saveIncidents();
                renderIncidentsTable();
            }
        }
    }
}

function updateAlertCounts() {
    const open = timelineEvents.filter(e => e.status === 'open').length;
    const investigating = timelineEvents.filter(e => e.status === 'investigating').length;
    const resolved = timelineEvents.filter(e => e.status === 'resolved').length;
    const fp = timelineEvents.filter(e => e.status === 'false_positive').length;

    document.getElementById('alerts-count-open').textContent = open;
    document.getElementById('alerts-count-investigating').textContent = investigating;
    document.getElementById('alerts-count-resolved').textContent = resolved;
    document.getElementById('alerts-count-fp').textContent = fp;
}

function createCaseFromAlert(alertId) {
    const alert = timelineEvents.find(e => e.id === alertId);
    if (!alert) {
        showToast('Alert not found.', 'danger');
        return;
    }
    const data = {
        title: alert.eventType,
        severity: alert.severity || 'medium',
        status: 'open',
        assignedTo: null,
        description: `Case created from alert: ${alert.details}`,
        alerts: [alert.id],
        evidence: [{ type: 'alert', id: alert.id }]
    };
    const newCase = createCase(data);
    showToast(`Case #${newCase.id} created from alert.`, 'success');
    switchView('cases');
}

function updateCaseMetrics() {
    const container = document.getElementById('case-metrics');
    if (!container) return;
    const open = cases.filter(c => c.status === 'open').length;
    const investigating = cases.filter(c => c.status === 'investigating').length;
    const resolved = cases.filter(c => c.status === 'resolved').length;
    let avgTime = 0;
    const resolvedCases = cases.filter(c => c.status === 'resolved' && c.closedAt && c.createdAt);
    if (resolvedCases.length > 0) {
        const total = resolvedCases.reduce((sum, c) => sum + (c.closedAt - c.createdAt), 0);
        avgTime = total / resolvedCases.length / 60000; 
    }
    container.innerHTML = `
        <div class="stat-card"><div class="stat-info"><h3>${open}</h3><p>Open</p></div></div>
        <div class="stat-card"><div class="stat-info"><h3>${investigating}</h3><p>Investigating</p></div></div>
        <div class="stat-card"><div class="stat-info"><h3>${resolved}</h3><p>Resolved</p></div></div>
        <div class="stat-card"><div class="stat-info"><h3>${avgTime.toFixed(1)}m</h3><p>Avg Resolution Time</p></div></div>
    `;
}

function renderAlertsTable() {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;

    const statusFilter = document.getElementById('alert-status-filter')?.value || 'all';
    const severityFilter = document.getElementById('alert-severity-filter')?.value || 'all';
    const searchTerm = document.getElementById('alert-search')?.value?.toLowerCase() || '';

    let alerts = timelineEvents.slice();

    if (statusFilter !== 'all') {
        alerts = alerts.filter(a => a.status === statusFilter);
    }
    if (severityFilter !== 'all') {
        alerts = alerts.filter(a => a.severity === severityFilter);
    }
    if (searchTerm) {
    alerts = alerts.filter(a =>
        (a.details && a.details.toLowerCase().includes(searchTerm)) ||
        (a.src && typeof a.src === 'string' && a.src.includes(searchTerm)) ||
        (a.dst && typeof a.dst === 'string' && a.dst.includes(searchTerm)) ||
        (a.eventType && a.eventType.toLowerCase().includes(searchTerm)) ||
        (a.notes && a.notes.some(n => typeof n === 'string' && n.toLowerCase().includes(searchTerm))) ||
        (a.falsePositiveReason && a.falsePositiveReason.toLowerCase().includes(searchTerm))
      );
    }
    alerts.sort((a, b) => (b.eventTimestamp || 0) - (a.eventTimestamp || 0));

    tbody.innerHTML = '';
    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No alerts match the filters.</td></tr>';
        return;
    }

    alerts.forEach(alert => {
        const row = document.createElement('tr');
        const statusClass = alert.status === 'open' ? 'status-open' :
                            alert.status === 'investigating' ? 'status-investigating' :
                            alert.status === 'resolved' ? 'status-resolved' :
                            'status-fp';
        const statusLabel = alert.status === 'false_positive' ? 'FP' : alert.status;

        let notesDisplay = '';
        if (alert.falsePositiveReason) {
            notesDisplay = `⚠️ ${alert.falsePositiveReason}`;
        } else if (alert.notes && alert.notes.length > 0) {
            notesDisplay = alert.notes.join('; ');
        }

        let actionsHtml = '';
        if (alert.status === 'open') {
            actionsHtml = `
                <button class="btn-action acknowledge" data-id="${alert.id}">Acknowledge</button>
                <button class="btn-action investigate" data-id="${alert.id}">🔍 Investigate</button>
                <button class="btn-action create-case" data-id="${alert.id}">→ Case</button>
                <button class="btn-action fp" data-id="${alert.id}">False Positive</button>
            `;
        } else if (alert.status === 'investigating') {
            actionsHtml = `
                <button class="btn-action resolve" data-id="${alert.id}">Resolve</button>
                <button class="btn-action create-case" data-id="${alert.id}">→ Case</button>
                <button class="btn-action fp" data-id="${alert.id}">False Positive</button>
            `;
        } else {
            actionsHtml = `<span>—</span>`;
        }

        row.innerHTML = `
            <td>${formatAlertTime(alert)}</td>
            <td><span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
            <td>${alert.eventType}</td>
            <td>${alert.details}${alert.src ? ` (${alert.src} → ${alert.dst})` : ''}</td>
            <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
            <td>${notesDisplay}</td>
            <td>${actionsHtml}</td>
        `;
        tbody.appendChild(row);

    row.addEventListener('click', function(e) {
        if (e.target.closest('button')) return;
        openAlertInvestigation(alert.id);
    });


      });

        tbody.querySelectorAll('.btn-action.create-case').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const alertId = this.dataset.id;
            createCaseFromAlert(alertId);
            });
        });

        tbody.querySelectorAll('.btn-action.investigate').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            openAlertInvestigation(id);
        });
    });

    tbody.querySelectorAll('.btn-action.acknowledge').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            updateAlertStatus(id, 'investigating');
        });
    });
    tbody.querySelectorAll('.btn-action.resolve').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            updateAlertStatus(id, 'resolved');
        });
    });
    tbody.querySelectorAll('.btn-action.fp').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
           showFpModal(id);
        });
    });

    updateAlertCounts();
    updateAlertMetrics();
}

document.getElementById('alert-status-filter')?.addEventListener('change', renderAlertsTable);
document.getElementById('alert-severity-filter')?.addEventListener('change', renderAlertsTable);
document.getElementById('alert-search')?.addEventListener('input', renderAlertsTable);
document.getElementById('alert-clear-filters')?.addEventListener('click', function() {
    document.getElementById('alert-status-filter').value = 'all';
    document.getElementById('alert-severity-filter').value = 'all';
    document.getElementById('alert-search').value = '';
    renderAlertsTable();
});

let replayState = {
    events: [],
    currentIndex: 0,
    isPlaying: false,
    intervalId: null,
    speed: 5, 
    baseInterval: 1000,
};

function openReplayModal() {
    const modal = document.getElementById('replay-modal');
    if (!modal) return;
    replayState.events = timelineEvents.slice().sort((a, b) => (a.eventTimestamp || 0) - (b.eventTimestamp || 0));
    replayState.currentIndex = 0;
    replayState.isPlaying = false;
    if (replayState.intervalId) {
        clearInterval(replayState.intervalId);
        replayState.intervalId = null;
    }
    renderReplayEvents();
    updateReplayProgress();
    document.getElementById('replay-play').style.display = 'inline-flex';
    document.getElementById('replay-pause').style.display = 'none';
    modal.classList.remove('hidden');
    const scrubber = document.getElementById('replay-scrubber');
    if (scrubber) scrubber.max = Math.max(replayState.events.length - 1, 0);
}

function closeReplayModal() {
    document.getElementById('replay-modal')?.classList.add('hidden');
    if (replayState.intervalId) {
        clearInterval(replayState.intervalId);
        replayState.intervalId = null;
    }
    replayState.isPlaying = false;
}

function renderReplayEvents() {
    const container = document.getElementById('replay-events-container');
    if (!container) return;
    if (replayState.events.length === 0) {
        container.innerHTML = '<div class="replay-empty">No events to replay.</div>';
        return;
    }
    container.querySelectorAll('.replay-event-item').forEach(el => {
      el.addEventListener('click', function() {
          const idx = parseInt(this.dataset.index);
          const ev = replayState.events[idx];
          if (ev) showPacketDrilldown(ev);
          });
    });
    let html = '';
    replayState.events.forEach((ev, idx) => {
        const isActive = idx === replayState.currentIndex;
        const severityClass = ev.severity || 'low';
        const mitreBadge = ev.mitre ? `<span class="mitre-badge">${ev.mitre}</span>` : '';
        html += `
            <div class="replay-event-item ${isActive ? 'active' : ''}" data-index="${idx}">
                <span class="event-time">${formatAlertTime(ev)}</span>
                <span class="event-type">${ev.eventType || 'Event'} ${mitreBadge}</span>
                <span class="event-severity severity-${severityClass}">${severityClass.toUpperCase()}</span>
                <span class="event-details">${ev.details || ''}</span>
            </div>
        `;
    });
    container.innerHTML = html;
    const activeEl = container.querySelector('.replay-event-item.active');
    if (activeEl) {
        activeEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
}

function updateReplayProgress() {
    const total = replayState.events.length;
    const current = replayState.currentIndex;
    const progress = total > 1 ? (current / (total - 1)) * 100 : 0;
    document.getElementById('replay-progress-fill').style.width = Math.min(progress, 100) + '%';
    document.getElementById('replay-progress-text').textContent = `${current + 1} / ${total}`;
    document.getElementById('replay-scrubber').value = current;

    const seenStages = new Set();
    for (let i = 0; i <= replayState.currentIndex; i++) {
        const ev = replayState.events[i];
        if (ev.src) {
            const stage = STAGE_MAP[ev.eventType] || ev.eventType;
            const phase = PHASE_MAP[stage];
            if (phase) seenStages.add(phase);
        }
    }
    const allPhases = PHASE_ORDER; 
    let chainHtml = '';
    allPhases.forEach(p => {
        const done = seenStages.has(p);
        chainHtml += `<span class="mini-phase ${done ? 'done' : 'pending'}">${p}</span>`;
    });
    const killchainContainer = document.getElementById('replay-killchain');
    if (killchainContainer) {
        killchainContainer.innerHTML = `<strong>Attack Chain:</strong> ${chainHtml}`;
    }

    renderReplayEvents();
}
function replayStep() {
    if (replayState.currentIndex < replayState.events.length - 1) {
        replayState.currentIndex++;
        updateReplayProgress();
    } else {
        replayPause();
        replayState.currentIndex = 0; 
        updateReplayProgress();
    }
}

function replayPlay() {
    if (replayState.events.length === 0) return;
    if (replayState.currentIndex >= replayState.events.length - 1) {
        replayState.currentIndex = 0;
        updateReplayProgress();
    }
    replayState.isPlaying = true;
    document.getElementById('replay-play').style.display = 'none';
    document.getElementById('replay-pause').style.display = 'inline-flex';
    const speedMultiplier = parseInt(document.getElementById('replay-speed-select').value) || 5;
    const intervalMs = 1000 / speedMultiplier;
    if (replayState.intervalId) clearInterval(replayState.intervalId);
    replayState.intervalId = setInterval(replayStep, intervalMs);
}

function replayPause() {
    replayState.isPlaying = false;
    if (replayState.intervalId) {
        clearInterval(replayState.intervalId);
        replayState.intervalId = null;
    }
    document.getElementById('replay-play').style.display = 'inline-flex';
    document.getElementById('replay-pause').style.display = 'none';
}

function replayStop() {
    replayPause();
    replayState.currentIndex = 0;
    updateReplayProgress();
    document.getElementById('replay-scrubber').value = 0;
}

function replayRestart() {
    replayStop();
    replayPlay();
}

document.getElementById('replay-play')?.addEventListener('click', replayPlay);
document.getElementById('replay-pause')?.addEventListener('click', replayPause);
document.getElementById('replay-stop')?.addEventListener('click', replayStop);
document.getElementById('replay-restart')?.addEventListener('click', replayRestart);

document.getElementById('replay-speed-select')?.addEventListener('change', function() {
    if (replayState.isPlaying) {
        replayPause();
        replayPlay();
    }
});

document.getElementById('replay-scrubber')?.addEventListener('input', function() {
    const val = parseInt(this.value);
    if (val >= 0 && val < replayState.events.length) {
        replayState.currentIndex = val;
        updateReplayProgress();
        if (replayState.isPlaying) {
            replayPause();
            replayPlay();
        }
    }
});

document.getElementById('close-replay-modal')?.addEventListener('click', closeReplayModal);
document.getElementById('replay-modal')?.addEventListener('click', function(e) {
    if (e.target === this) closeReplayModal();
});

document.getElementById('replay-timeline-btn')?.addEventListener('click', openReplayModal);
document.getElementById('replay-timeline-btn-alerts')?.addEventListener('click', openReplayModal);


function loadCases() {
    try {
        const stored = localStorage.getItem('neoShieldCases');
        if (stored) {
            cases = JSON.parse(stored);
            nextCaseId = cases.reduce((max, c) => Math.max(max, c.id), 0) + 1;
        } else {
            cases = [];
            nextCaseId = 1;
        }
    } catch (e) {
        cases = [];
        nextCaseId = 1;
    }
}

function saveCases() {
    try {
        localStorage.setItem('neoShieldCases', JSON.stringify(cases));
    } catch (e) {}
}

function renderCasesTable() {
    const tbody = document.getElementById('cases-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (cases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No cases created yet. Start one!</td></tr>';
        updateCaseMetrics();
        return;
    }
    const sorted = [...cases].sort((a, b) => b.updatedAt - a.updatedAt);
    sorted.forEach(c => {
        const row = document.createElement('tr');
        const severityClass = c.severity || 'medium';
        const statusClass = c.status || 'open';
        const alertCount = c.alerts ? c.alerts.length : 0;
        row.innerHTML = `
            <td>#${c.id}</td>
            <td><strong>${c.title}</strong></td>
            <td><span class="severity-${severityClass}">${severityClass.toUpperCase()}</span></td>
            <td><span class="priority-badge">${c.priority || 'P2'}</span></td>
            <td><span class="status-badge status-${statusClass}">${statusClass.toUpperCase()}</span></td>
            <td>${alertCount}</td>
            <td>${c.assignedTo || '—'}</td>
            <td>${new Date(c.updatedAt).toLocaleDateString()} ${new Date(c.updatedAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</td>
            <td>
                <button class="btn-action view-case" data-id="${c.id}">View</button>
                <button class="btn-action edit-case" data-id="${c.id}">Edit</button>
                <button class="btn-action delete-case" data-id="${c.id}" style="background: #ef4444; color: white;">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
    updateCaseMetrics();
    
    tbody.querySelectorAll('.view-case').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            openCaseDetail(id);
        });
    });
    tbody.querySelectorAll('.edit-case').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            openCaseEdit(id);
        });
    });
    tbody.querySelectorAll('.delete-case').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            deleteCase(id);
        });
    });
}

function openCaseDetail(caseId) {
    const c = cases.find(c => c.id === caseId);
    if (!c) return;
    currentCaseDetailId = caseId;
    const modal = document.getElementById('case-detail-modal');
    const title = document.getElementById('case-detail-title');
    const content = document.getElementById('case-detail-content');
    const notesList = document.getElementById('case-notes-list');

    title.textContent = `Case #${c.id}: ${c.title}`;
    let html = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px;">
            <div><strong>Severity:</strong> <span class="severity-${c.severity}">${c.severity.toUpperCase()}</span></div>
            <div><strong>Priority:</strong> ${c.priority || 'P2'}</div>
            <div><strong>Status:</strong> <span class="status-badge status-${c.status}">${c.status.toUpperCase()}</span></div>
            <div><strong>Assigned To:</strong> ${c.assignedTo || '—'}</div>
            <div><strong>Created:</strong> ${new Date(c.createdAt).toLocaleString()}</div>
            <div><strong>Updated:</strong> ${new Date(c.updatedAt).toLocaleString()}</div>
            <div><strong>Closed:</strong> ${c.closedAt ? new Date(c.closedAt).toLocaleString() : '—'}</div>
        </div>
        <p><strong>Description:</strong> ${c.description || 'No description.'}</p>
        <p><strong>Linked Alerts:</strong> ${c.alerts && c.alerts.length ? c.alerts.map(id => {
            const ev = timelineEvents.find(e => e.id === id);
            return ev ? `${ev.eventType} (${formatAlertTime(ev)})` : `Alert #${id}`;
        }).join(', ') : 'None'}</p>
        <p><strong>Evidence:</strong> ${c.evidence && c.evidence.length ? c.evidence.map(ev => {
            if (ev.type === 'alert') {
                const alert = timelineEvents.find(e => e.id === ev.id);
                return alert ? `<span class="evidence-link" data-type="alert" data-id="${ev.id}">${alert.eventType}</span>` : `Alert #${ev.id}`;
            } else if (ev.type === 'packet') {
                return `<span class="evidence-link" data-type="packet" data-id="${ev.id}">Packet #${ev.id}</span>`;
            }
            return 'Unknown evidence';
        }).join(', ') : 'None'}</p>

        <p><strong>Notes:</strong></p>
        <div id="case-notes-list-detail">
            ${c.notes && c.notes.length ? c.notes.map(n => `<div>${new Date(n.timestamp).toLocaleString()}: ${n.text}</div>`).join('') : 'No notes.'}
        </div>
    `;
    content.innerHTML = html;
    
    content.dataset.caseId = caseId;

    modal.classList.remove('hidden');
}

document.addEventListener('click', function(e) {
    const link = e.target.closest('.evidence-link');
    if (!link) return;
    const type = link.dataset.type;
    const id = link.dataset.id;
    if (type === 'alert') {
        
        const alert = timelineEvents.find(a => a.id === id);
        if (alert) showPacketDrilldown(alert);
    } else if (type === 'packet') {
        
        const packet = globalPacketData.find(p => p.id === id);
        if (packet) openDrawer(packet);
    }
});


let currentCaseDetailId = null;




function openCaseEdit(caseId) {
    const c = cases.find(c => c.id === caseId);
    if (!c) return;
    
    document.getElementById('case-modal-title').textContent = `Edit Case #${c.id}`;
    document.getElementById('case-title').value = c.title;
    document.getElementById('case-severity').value = c.severity;
    document.getElementById('case-status').value = c.status;
    document.getElementById('case-assigned').value = c.assignedTo || '';
    document.getElementById('case-description').value = c.description || '';
    
    populateAlertSelect(c.alerts || []);
    
    document.getElementById('case-form').dataset.caseId = caseId;
    document.getElementById('case-modal').classList.remove('hidden');
}

function openCaseNew() {
    document.getElementById('case-modal-title').textContent = 'New Case';
    document.getElementById('case-form').reset();
    document.getElementById('case-title').value = '';
    document.getElementById('case-severity').value = 'high';
    document.getElementById('case-status').value = 'open';
    document.getElementById('case-assigned').value = '';
    document.getElementById('case-description').value = '';
    populateAlertSelect([]);
    document.getElementById('case-form').dataset.caseId = '';
    document.getElementById('case-modal').classList.remove('hidden');
}

function populateAlertSelect(selectedIds) {
    const select = document.getElementById('case-alerts-select');
    if (!select) return;
    select.innerHTML = '';
    
    const alerts = timelineEvents; 
    alerts.forEach(ev => {
        const opt = document.createElement('option');
        opt.value = ev.id;
        opt.textContent = `${formatAlertTime(ev)} - ${ev.eventType} (${ev.severity})`;
        if (selectedIds && selectedIds.includes(ev.id)) {
            opt.selected = true;
        }
        select.appendChild(opt);
    });
}

function createCase(data) {
    const newCase = {
        id: generateCaseId(),
        title: data.title || 'Untitled Case',
        severity: data.severity || 'medium',
        priority: data.priority || 'P2',          
        status: data.status || 'open',
        assignedTo: data.assignedTo || null,
        alerts: data.alerts || [],
        evidence: data.evidence || [],            
        notes: [],
        createdAt: Date.now(),
        updatedAt: Date.now(),
        closedAt: null,                           
        description: data.description || '',
    };
    cases.unshift(newCase);
    saveCases();
    renderCasesTable();
    updateCaseMetrics();
    rebuildIndices();
    return newCase;
}

function updateCase(caseId, updates) {
    const idx = cases.findIndex(c => c.id === caseId);
    if (idx === -1) return;
    const oldCase = cases[idx];
    const updated = { ...oldCase, ...updates, updatedAt: Date.now() };
    if (updates.status === 'resolved' && oldCase.status !== 'resolved') {
        updated.closedAt = Date.now();
    } else if (updates.status !== 'resolved') {
        updated.closedAt = null;
    }
    
    cases[idx] = updated;
    saveCases();
    renderCasesTable();
    updateCaseMetrics();     
    rebuildIndices();
    return updated;
}

function deleteCase(caseId) {
    if (!confirm('Are you sure you want to delete this case?')) return;
    cases = cases.filter(c => c.id !== caseId);
    saveCases();
    renderCasesTable();
    rebuildIndices();
}

function addCaseNote(caseId, note) {
    const idx = cases.findIndex(c => c.id === caseId);
    if (idx === -1) return;
    const c = cases[idx];
    c.notes.push({ timestamp: Date.now(), text: note });
    c.updatedAt = Date.now();
    saveCases();
    renderCasesTable();
    renderCaseDetail(caseId); 
}

function renderCaseDetail(caseId) {
    const modal = document.getElementById('case-detail-modal');
    if (modal && !modal.classList.contains('hidden')) {
        openCaseDetail(caseId);
    }
}

document.getElementById('case-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const caseId = this.dataset.caseId;
    const title = document.getElementById('case-title').value.trim();
    if (!title) {
        showToast('Title is required.', 'warning');
        return;
    }
    const severity = document.getElementById('case-severity').value;
    const status = document.getElementById('case-status').value;
    const assignedTo = document.getElementById('case-assigned').value.trim() || null;
    const description = document.getElementById('case-description').value.trim() || '';
    const alertsSelect = document.getElementById('case-alerts-select');
    const selectedAlerts = Array.from(alertsSelect.selectedOptions).map(opt => opt.value);
    const priority = document.getElementById('case-priority').value;

    const data = { title, severity, priority, status, assignedTo, description, alerts: selectedAlerts };
    if (caseId) {
        updateCase(parseInt(caseId), data);
        showToast('Case updated.', 'success');
    } else {
        createCase(data);
        showToast('Case created.', 'success');
    }
    document.getElementById('case-modal').classList.add('hidden');
    renderCasesTable();
});

document.addEventListener('DOMContentLoaded', () => {
  initAnalyticsCharts(); 
  initGeoSpecificCharts();

   loadCases();
    loadIOCs();
    loadRules();
    loadResponsePolicies();  
    loadActionLogs(); 
    renderMitreCoverage();
    loadAssets();
    renderAssetsTable();
    updateAssetAlertCounts();
    updateUEBA();
    updateAlertMetrics();
    rebuildIndices();
    loadIncidents();
    renderIncidentsTable();

    timelineEvents.forEach(alert => {
    if (!alert.eventTimestamp && alert.timestamp) {
        const today = new Date();
        const parts = alert.timestamp.split(':');
        if (parts.length === 3) {
            today.setHours(parseInt(parts[0]), parseInt(parts[1]), parseInt(parts[2]), 0);
            alert.eventTimestamp = today.getTime();
        } else {
            alert.eventTimestamp = Date.now();
        }
    }
});

  setTimeout(() => {
    refreshHostRisk();
    updateFlowAnalysisTable();
    updateHostRiskChart();
    updateGeoStats(); 
    updateTopIOCWidget();
  }, 500);
});

document.getElementById('case-add-note-btn')?.addEventListener('click', function() {
    const input = document.getElementById('case-note-input');
    const note = input.value.trim();
    if (!note) return;
    const caseId = currentCaseDetailId;
    if (!caseId) return;
    addCaseNote(caseId, note);
    input.value = '';
});

document.getElementById('new-case-btn')?.addEventListener('click', openCaseNew);
document.getElementById('close-case-modal')?.addEventListener('click', function() {
    document.getElementById('case-modal').classList.add('hidden');
});
document.getElementById('cancel-case-btn')?.addEventListener('click', function() {
    document.getElementById('case-modal').classList.add('hidden');
});
document.getElementById('close-case-detail-modal')?.addEventListener('click', function() {
    document.getElementById('case-detail-modal').classList.add('hidden');
});
document.getElementById('case-detail-close')?.addEventListener('click', function() {
    document.getElementById('case-detail-modal').classList.add('hidden');
});


function loadIOCs() {
    try {
        const stored = localStorage.getItem('neoShieldIOCs');
        if (stored) {
            iocs = JSON.parse(stored);
            iocs = iocs.map(i => ({
                ...i,
                severity: i.severity || 'medium',
                expiresAt: i.expiresAt || null,
                matchCount: i.matchCount || 0,
                lastSeen: i.lastSeen || null,
                firstSeen: i.firstSeen || null,   
                hits: i.hits || [],
                alertIds: i.alertIds || [],      
            }));
            nextIocId = iocs.reduce((max, i) => Math.max(max, i.id), 0) + 1;
        } else {
            iocs = [];
            nextIocId = 1;
        }
    } catch (e) {
        iocs = [];
        nextIocId = 1;
    }
}

function saveIOCs() {
    try {
        localStorage.setItem('neoShieldIOCs', JSON.stringify(iocs));
    } catch (e) {}
}

function addIOC(type, value, description = '', severity = 'medium', expiresAt = null, autoBlock = false) {
    const ioc = {
        id: nextIocId++,
        type,
        value: value.trim(),
        description: description.trim() || '',
        severity: severity,
        expiresAt: expiresAt,
        autoBlock,
        matchCount: 0,
        firstSeen: null,          
        lastSeen: null,
        hits: [],
        alertIds: [],             
        addedAt: Date.now(),
    };
    iocs.push(ioc);
    saveIOCs();
    renderIOCs();
    if (type === 'ip' && autoBlock) {
        blockedIPs.add(value);
        sendBlockedIPsToBackend();
    }
    rebuildIndices();
    return ioc;
}

function deleteIOC(id) {
    const ioc = iocs.find(i => i.id === id);
    if (ioc && ioc.type === 'ip' && ioc.autoBlock) {
        blockedIPs.delete(ioc.value);
        sendBlockedIPsToBackend();
    }
    iocs = iocs.filter(i => i.id !== id);
    saveIOCs();
    renderIOCs();
    rebuildIndices();
}

function renderIOCs() {
    const tbody = document.getElementById('ioc-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No IOCs added yet.</td></tr>';
        return;
    }
    iocs.slice().reverse().forEach(ioc => {
        const row = document.createElement('tr');
        const severityClass = ioc.severity || 'medium';
        const severityLabel = severityClass.toUpperCase();
        const lastSeenStr = ioc.lastSeen ? new Date(ioc.lastSeen).toLocaleString() : '—';
        const blockStatus = (ioc.type === 'ip' && blockedIPs.has(ioc.value)) ? 'Unblock' : 'Block';
        const blockBtnClass = blockedIPs.has(ioc.value) ? 'btn-action unblock' : 'btn-action block';
        const blockedIcon = blockedIPs.has(ioc.value) ? '🔒 ' : '';
        const firstSeenStr = ioc.firstSeen ? new Date(ioc.firstSeen).toLocaleString() : '—';

        
        let affectedHosts = '—';
        if (ioc.hits && ioc.hits.length > 0) {
            const hosts = new Set();
            ioc.hits.forEach(hit => {
                if (hit.src) hosts.add(hit.src);
                if (hit.dst) hosts.add(hit.dst);
            });
            const hostList = Array.from(hosts);
            affectedHosts = hostList.length + ' host' + (hostList.length > 1 ? 's' : '');
            
            const tooltip = hostList.slice(0, 5).join(', ') + (hostList.length > 5 ? '…' : '');
            affectedHosts = `<span title="${tooltip}">${affectedHosts}</span>`;
        }

        row.innerHTML = `
            <td><span class="ioc-type-badge">${ioc.type.toUpperCase()}</span></td>
            <td><code>${blockedIcon}${ioc.value}</code></td>
            <td><span class="severity-${severityClass}">${severityLabel}</span></td>
            <td>${ioc.matchCount || 0}</td>
            <td>${affectedHosts}</td>   
            <td>${firstSeenStr}</td>   
            <td>${lastSeenStr}</td>
            <td>${ioc.description || '—'}</td>
            <td>
                <button class="btn-action view-ioc-hits" data-id="${ioc.id}" title="View Hits">📊 Hits</button>
                <button class="btn-action ${blockBtnClass}" data-id="${ioc.id}" title="Block/Unblock IP">${blockStatus}</button>
                <button class="btn-action delete-ioc" data-id="${ioc.id}" style="background:#ef4444;color:white;">Delete</button>
            </td>
        `;
        row.addEventListener('click', function(e) {
            if (e.target.closest('button')) return;
            const id = parseInt(this.querySelector('.view-ioc-hits')?.dataset.id);
            if (id) showIocHits(id);
        });
        tbody.appendChild(row);
    });

    
    tbody.querySelectorAll('.btn-action.block, .btn-action.unblock').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            toggleIocBlock(id);
        });
    });
    tbody.querySelectorAll('.delete-ioc').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            showConfirmModal('Delete IOC', `Are you sure you want to delete this IOC?`, () => deleteIOC(id));
        });
    });
    tbody.querySelectorAll('.view-ioc-hits').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            showIocHits(id);
        });
    });
    updateTopIOCWidget();
}
function toggleIocBlock(iocId) {
    const ioc = iocs.find(i => i.id === iocId);
    if (!ioc) return;
    if (ioc.type !== 'ip') {
        showToast('Only IP IOCs can be blocked.', 'warning');
        return;
    }
    const currentlyBlocked = blockedIPs.has(ioc.value);
    if (currentlyBlocked) {
        blockedIPs.delete(ioc.value);
        ioc.autoBlock = false;
        sendUnblockedIPsToBackend(); 
        showToast(`Unblocked ${ioc.value}`, 'success');
    } else {
        blockedIPs.add(ioc.value);
        ioc.autoBlock = true;
        sendBlockedIPsToBackend();
        showToast(`Blocked ${ioc.value}`, 'success');
    }
    saveIOCs();
    renderIOCs();
}
function showIocHits(iocId) {
    const ioc = iocs.find(i => i.id === iocId);
    if (!ioc) return;
    const modal = document.getElementById('ioc-hits-modal');
    const title = document.getElementById('ioc-hits-title');
    const content = document.getElementById('ioc-hits-content');
    title.textContent = `${ioc.value} (${ioc.type})`;

   if (!ioc.hits || ioc.hits.length === 0) {
        content.innerHTML = '<p>No hits recorded yet.</p>';
        return;
    }

    
    const hosts = new Set();
    ioc.hits.forEach(hit => {
        if (hit.src) hosts.add(hit.src);
        if (hit.dst) hosts.add(hit.dst);
    });
    const hostList = Array.from(hosts);
    let html = `<div class="affected-hosts-summary"><strong>Affected Hosts (${hostList.length}):</strong> ${hostList.join(', ')}</div>`;

    
    if (ioc.alertIds && ioc.alertIds.length > 0) {
        const alertCount = ioc.alertIds.length;
        html += `<div style="margin: 8px 0;"><strong>Related Alerts:</strong> ${alertCount} alert${alertCount > 1 ? 's' : ''}</div>`;
        
        const preview = ioc.alertIds.slice(0, 5).join(', ');
        if (ioc.alertIds.length > 5) html += `<span title="${ioc.alertIds.join(', ')}"> (${preview}…)</span>`;
    }

    
    html += `<table class="packet-table"><thead><tr><th>Time</th><th>Source</th><th>Destination</th></tr></thead><tbody>`;
    ioc.hits.slice().reverse().forEach(hit => {
        const time = new Date(hit.timestamp).toLocaleString();
        html += `<tr><td>${time}</td><td>${hit.src}</td><td>${hit.dst}</td></tr>`;
    });
    html += `</tbody></table>`;
    content.innerHTML = html;
    modal.classList.remove('hidden');
}

document.getElementById('close-ioc-hits-modal')?.addEventListener('click', () => {
    document.getElementById('ioc-hits-modal').classList.add('hidden');
});
document.getElementById('ioc-hits-modal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
});

function openIocModal(iocId = null) {
    const modal = document.getElementById('ioc-modal');
    const title = document.getElementById('ioc-modal-title');
    const form = document.getElementById('ioc-form');
    if (iocId) {
        const ioc = iocs.find(i => i.id === iocId);
        if (!ioc) return;
        title.textContent = 'Edit IOC';
        document.getElementById('ioc-type').value = ioc.type;
        document.getElementById('ioc-value').value = ioc.value;
        document.getElementById('ioc-description').value = ioc.description || '';
        document.getElementById('ioc-auto-block').checked = ioc.autoBlock;
        form.dataset.iocId = iocId;
    } else {
        title.textContent = 'Add IOC';
        form.reset();
        form.dataset.iocId = '';
    }
    modal.classList.remove('hidden');
}

document.getElementById('add-ioc-btn')?.addEventListener('click', () => openIocModal());
document.getElementById('close-ioc-modal')?.addEventListener('click', () => {
    document.getElementById('ioc-modal').classList.add('hidden');
});
document.getElementById('cancel-ioc-btn')?.addEventListener('click', () => {
    document.getElementById('ioc-modal').classList.add('hidden');
});

document.getElementById('ioc-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const bulkText = document.getElementById('bulk-import-text').value.trim();
    if (bulkText) {
        
        const lines = bulkText.split('\n').map(line => line.trim()).filter(line => line);
        let added = 0;
        for (const line of lines) {
            
            let parts = line.split(':');
            let type = 'ip', value = parts[0], description = '';
            if (parts.length >= 2) {
                type = parts[0].toLowerCase();
                value = parts[1];
                description = parts.slice(2).join(':') || '';
            }
            
            if (!['ip', 'domain', 'hash', 'asn'].includes(type)) type = 'ip';
            if (value) {
                addIOC(type, value, description, 'high', null, false);
                added++;
            }
        }
        if (added > 0) {
            showToast(`Added ${added} IOCs via bulk import.`, 'success');
        } else {
            showToast('No valid IOCs found.', 'warning');
        }
        document.getElementById('ioc-modal').classList.add('hidden');
        return;
    }

    
    const type = document.getElementById('ioc-type').value;
    const value = document.getElementById('ioc-value').value.trim();
    if (!value) {
        showToast('IOC value is required.', 'warning');
        return;
    }
    const description = document.getElementById('ioc-description').value;
    const severity = document.getElementById('ioc-severity').value;
    const expiresInput = document.getElementById('ioc-expires').value;
    const expiresAt = expiresInput ? new Date(expiresInput).getTime() : null;
    const autoBlock = document.getElementById('ioc-auto-block').checked;
    const iocId = this.dataset.iocId;

    if (iocId) {
        
        const idx = iocs.findIndex(i => i.id === parseInt(iocId));
        if (idx !== -1) {
            const old = iocs[idx];
            if (old.type === 'ip' && old.autoBlock) blockedIPs.delete(old.value);
            iocs.splice(idx, 1);
        }
    }
    addIOC(type, value, description, severity, expiresAt, autoBlock);
    document.getElementById('ioc-modal').classList.add('hidden');
    showToast(`IOC ${value} added.`, 'success');
});

function isIocExpired(ioc) {
    if (!ioc.expiresAt) return false;
    return Date.now() > ioc.expiresAt;
}

function matchIOCs() {
    if (iocs.length === 0) return;

    
    const ipMap = new Map();
    const domainMap = new Map();
    const hashMap = new Map();
    const asnMap = new Map();

    iocs.forEach(i => {
        if (isIocExpired(i)) return;
        if (i.type === 'ip') ipMap.set(i.value, i);
        else if (i.type === 'domain') domainMap.set(i.value, i);
        else if (i.type === 'hash') hashMap.set(i.value, i);
        else if (i.type === 'asn') asnMap.set(i.value, i);
    });

    for (const pkt of globalPacketData) {
        
        let ioc = ipMap.get(pkt.src) || ipMap.get(pkt.dst);
        if (ioc) {
            const matchedIP = ipMap.has(pkt.src) ? pkt.src : pkt.dst;
            if (shouldAlert(`ioc_ip_${matchedIP}`, 300)) {
                const evidence = {
                  iocType: ioc.type,
                  iocValue: ioc.value,
                  matchedIP: matchedIP,
                  mitre: null
              };

                const alertId = addTimelineEvent(
                  `IOC Match (${ioc.type.toUpperCase()})`,
                  ioc.severity || 'high',
                  `Traffic matches IOC IP: ${matchedIP} (${ioc.description || 'no description'})`,
                  pkt.src, pkt.dst,
                  { iocType: ioc.type, iocValue: matchedIP },
                  90,
                  'IOC',
                  null,
                  evidence
              );
                recordIocHit(ioc, pkt, alertId.id);
                if (ioc.autoBlock) {
                    blockedIPs.add(matchedIP);
                    sendBlockedIPsToBackend();
                }
            }
        }

        
        if (pkt.payload && domainMap.size > 0) {
            const payload = pkt.payload.toLowerCase();
            for (const [domain, ioc] of domainMap) {
                if (payload.includes(domain.toLowerCase())) {
                    if (shouldAlert(`ioc_domain_${domain}`, 300)) {
                        const alertId = addTimelineEvent(
                            `IOC Match (Domain)`,
                            ioc.severity || 'high',
                            `Payload contains IOC domain: ${domain} (${ioc.description || ''})`,
                            pkt.src, pkt.dst,
                            { iocType: 'domain', iocValue: domain },
                            85,
                            'IOC'
                        );
                        recordIocHit(ioc, pkt, alertId.id);
                        if (ioc.autoBlock) {
                            blockedIPs.add(pkt.src);
                            sendBlockedIPsToBackend();
                        }
                    }
                    break;
                }
            }
        }

        
        if (pkt.payload && hashMap.size > 0) {
            const hashRegex = /[a-fA-F0-9]{32,64}/g;
            const hashes = pkt.payload.match(hashRegex) || [];
            for (const h of hashes) {
                const ioc = hashMap.get(h);
                if (ioc) {
                    if (shouldAlert(`ioc_hash_${h}`, 300)) {
                        const alertId = addTimelineEvent(
                            `IOC Match (Hash)`,
                            ioc.severity || 'high',
                            `Payload contains IOC hash: ${h} (${ioc.description || ''})`,
                            pkt.src, pkt.dst,
                            { iocType: 'hash', iocValue: h },
                            85,
                            'IOC'
                        );
                        recordIocHit(ioc, pkt, alertId.id);
                    }
                    break;
                }
            }
        }

        
        if (asnMap.size > 0) {
            const srcGeo = geoCache.get(pkt.src);
            const dstGeo = geoCache.get(pkt.dst);
            const asnList = [];
            if (srcGeo && srcGeo.asn) asnList.push(srcGeo.asn);
            if (dstGeo && dstGeo.asn) asnList.push(dstGeo.asn);
            for (const asn of asnList) {
                const ioc = asnMap.get(asn);
                if (ioc) {
                    if (shouldAlert(`ioc_asn_${asn}`, 300)) {
                        const alertId = addTimelineEvent(
                            `IOC Match (ASN)`,
                            ioc.severity || 'medium',
                            `Traffic involves IOC ASN: ${asn} (${ioc.description || ''})`,
                            pkt.src, pkt.dst,
                            { iocType: 'asn', iocValue: asn },
                            80,
                            'IOC'
                        );
                        recordIocHit(ioc, pkt, alertId.id);
                    }
                    break;
                }
            }
        }
    }
}

function getIocSeverity(ioc) {
    const hits = ioc.matchCount || 0;
    if (hits >= 50) return 'critical';
    if (hits >= 20) return 'high';
    if (hits >= 5) return 'medium';
    return 'low';
}

function recordIocHit(ioc, pkt, alertId = null) {
    if (!ioc.firstSeen) ioc.firstSeen = Date.now();
    ioc.matchCount = (ioc.matchCount || 0) + 1;
    ioc.lastSeen = Date.now();
    if (!ioc.hits) ioc.hits = [];
    ioc.hits.push({
        timestamp: Date.now(),
        src: pkt.src,
        dst: pkt.dst,
        packetId: pkt.id || null,
        alertId: alertId,     
    });
    if (alertId && !ioc.alertIds.includes(alertId)) {
        ioc.alertIds.push(alertId);
    }
    if (ioc.hits.length > 100) ioc.hits.shift();

    const newSeverity = getIocSeverity(ioc);
    if (newSeverity !== ioc.severity) {
        ioc.severity = newSeverity;
        

        addTimelineEvent('IOC Severity Escalated', newSeverity, `IOC ${ioc.value} severity changed to ${newSeverity} (${ioc.matchCount} hits)`, null, null, {_automated: true }, 60, 'IOC');
    }

    saveIOCs();
    renderIOCs();
    updateTopIOCWidget();
}


function showConfirmModal(title, message, onConfirm) {
    const modal = document.getElementById('confirm-modal');
    const titleEl = document.getElementById('confirm-modal-title');
    const messageEl = document.getElementById('confirm-modal-message');
    const confirmBtn = document.getElementById('confirm-ok-btn');
    const cancelBtn = document.getElementById('confirm-cancel-btn');
    const closeBtn = document.getElementById('close-confirm-modal');

    
    titleEl.textContent = title || 'Confirm';
    messageEl.textContent = message || 'Are you sure?';

    
    const newConfirmBtn = confirmBtn.cloneNode(true);
    const newCancelBtn = cancelBtn.cloneNode(true);
    const newCloseBtn = closeBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
    cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
    closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);

    
    modal.classList.remove('hidden');

    
    function closeModal() {
        modal.classList.add('hidden');
    }

    
    newConfirmBtn.addEventListener('click', function() {
        closeModal();
        if (typeof onConfirm === 'function') onConfirm();
    });

    
    function cancelHandler() {
        closeModal();
    }
    newCancelBtn.addEventListener('click', cancelHandler);
    newCloseBtn.addEventListener('click', cancelHandler);

    
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            closeModal();
        }
    });
}

document.getElementById('toggle-bulk-import')?.addEventListener('click', function() {
    const area = document.getElementById('bulk-import-area');
    area.style.display = area.style.display === 'none' ? 'block' : 'none';
});

function loadRules() {
    try {
        const stored = localStorage.getItem('neoShieldRules');
        if (stored) {
            rules = JSON.parse(stored);
            rules = rules.map(r => ({
                ...r,
                confidence: r.confidence !== undefined ? r.confidence : 85,
                actions: r.actions || { alert: true, block_ip: false, quarantine_host: false, add_ioc: false },
                matchMode: r.matchMode || 'AND',
                category: r.category || 'Other',
                mitre: r.mitre || '',
                cooldown: r.cooldown || 60,
            }));
            nextRuleId = rules.reduce((max, r) => Math.max(max, r.id), 0) + 1;
        } else {
            rules = [];
            nextRuleId = 1;
        }
    } catch (e) {
        rules = [];
        nextRuleId = 1;
    }
}

function saveRules() {
    try {
        localStorage.setItem('neoShieldRules', JSON.stringify(rules));
    } catch (e) {}
}

function addRule(name, severity, message, conditions, enabled = true, confidence = 85, actions = { alert: true, block_ip: false, quarantine_host: false, add_ioc: false }, matchMode = 'AND', category = 'Other', mitre = '', cooldown = 60) {
    const rule = {
        id: nextRuleId++,
        name: name.trim(),
        severity: severity || 'medium',
        message: message.trim() || 'Rule matched',
        conditions: conditions,
        enabled: enabled,
        confidence: Math.min(100, Math.max(0, confidence)),
        actions: actions,
        matchMode: matchMode,
        category: category,
        mitre: mitre,
        cooldown: cooldown,
        hits: 0,
        lastMatched: null,
        createdAt: Date.now(),
    };
    rules.push(rule);
    saveRules();
    renderRulesTable();
    return rule;
}

function updateRule(id, updates) {
    const idx = rules.findIndex(r => r.id === id);
    if (idx === -1) return;
    rules[idx] = { ...rules[idx], ...updates };
    saveRules();
    renderRulesTable();
    return rules[idx];
}

function deleteRule(id) {
    rules = rules.filter(r => r.id !== id);
    saveRules();
    renderRulesTable();
}

function renderRulesTable() {
    const tbody = document.getElementById('rules-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No custom rules defined.</td></tr>';
        return;
    }
    rules.slice().reverse().forEach(rule => {
        const row = document.createElement('tr');
        const severityClass = rule.severity || 'medium';
        const statusClass = rule.enabled ? 'status-resolved' : 'status-fp';
        const statusLabel = rule.enabled ? 'Enabled' : 'Disabled';
        const condStr = rule.conditions.map(c => `${c.field} ${c.operator} ${c.value}`).join(` ${rule.matchMode || 'AND'} `);
        const mitreBadge = rule.mitre ? `<span class="mitre-badge">${rule.mitre}</span>` : '';
        row.innerHTML = `
            <td><strong>${rule.name}</strong></td>
            <td><code>${condStr}</code></td>
            <td><span class="severity-${severityClass}">${severityClass.toUpperCase()}</span></td>
            <td>${rule.message}</td>
            <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
            <td>${rule.hits || 0}</td>
            <td>${rule.category || 'Other'}</td>
            <td>${mitreBadge}</td>
            <td>
                <button class="btn-action edit-rule" data-id="${rule.id}">Edit</button>
                <button class="btn-action delete-rule" data-id="${rule.id}" style="background:#ef4444;color:white;">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });

    
    tbody.querySelectorAll('.edit-rule').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            openRuleModal(id);
        });
    });
    tbody.querySelectorAll('.delete-rule').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            const rule = rules.find(r => r.id === id);
            showConfirmModal('Delete Rule', `Delete rule "${rule?.name}"?`, () => deleteRule(id));
        });
    });
}
function openRuleModal(ruleId = null) {
    const modal = document.getElementById('rule-modal');
    const title = document.getElementById('rule-modal-title');
    const form = document.getElementById('rule-form');
    const container = document.getElementById('conditions-container');
    container.innerHTML = '';

    if (ruleId) {
        const rule = rules.find(r => r.id === ruleId);
        if (!rule) return;
        title.textContent = 'Edit Rule';
        document.getElementById('rule-name').value = rule.name;
        document.getElementById('rule-severity').value = rule.severity;
        document.getElementById('rule-confidence').value = rule.confidence || 85;
        document.getElementById('rule-cooldown').value = rule.cooldown || 60;
        document.getElementById('rule-category').value = rule.category || 'Other';
        document.getElementById('rule-mitre').value = rule.mitre || '';
        document.getElementById('rule-message').value = rule.message;
        document.getElementById('rule-match-mode').value = rule.matchMode || 'AND';
        document.getElementById('rule-enabled').checked = rule.enabled;
        document.getElementById('action-block-ip').checked = rule.actions?.block_ip || false;
        document.getElementById('action-quarantine').checked = rule.actions?.quarantine_host || false;
        document.getElementById('action-add-ioc').checked = rule.actions?.add_ioc || false;
        rule.conditions.forEach(cond => addConditionRow(cond.field, cond.operator, cond.value));
        form.dataset.ruleId = ruleId;
    } else {
        title.textContent = 'New Rule';
        form.reset();
        document.getElementById('rule-enabled').checked = true;
        document.getElementById('action-alert').checked = true;
        document.getElementById('rule-confidence').value = 85;
        document.getElementById('rule-cooldown').value = 60;
        document.getElementById('rule-match-mode').value = 'AND';
        addConditionRow();
        form.dataset.ruleId = '';
    }
    modal.classList.remove('hidden');
}
document.getElementById('add-rule-btn')?.addEventListener('click', function() {
    openRuleModal();
});

function addConditionRow(field = '', operator = '', value = '') {
    const container = document.getElementById('conditions-container');
    const row = document.createElement('div');
    row.className = 'condition-row';
    row.style.display = 'flex';
    row.style.gap = '8px';
    row.style.marginBottom = '8px';
    row.style.alignItems = 'center';

    
    const fieldSelect = document.createElement('select');
    fieldSelect.className = 'modal-select';
    fieldSelect.style.flex = '1';
    RULE_FIELDS.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f.value;
        opt.textContent = f.label;
        if (f.value === field) opt.selected = true;
        fieldSelect.appendChild(opt);
    });

    
    const opSelect = document.createElement('select');
    opSelect.className = 'modal-select';
    opSelect.style.flex = '1';
    RULE_OPERATORS.forEach(o => {
        const opt = document.createElement('option');
        opt.value = o.value;
        opt.textContent = o.label;
        if (o.value === operator) opt.selected = true;
        opSelect.appendChild(opt);
    });

    
    const valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.className = 'modal-input';
    valInput.placeholder = 'Value';
    valInput.style.flex = '2';
    valInput.value = value || '';

    
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn-action';
    removeBtn.style.background = '#ef4444';
    removeBtn.style.color = 'white';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', function() {
        if (container.children.length > 1) {
            container.removeChild(row);
        } else {
            showToast('At least one condition is required.', 'warning');
        }
    });

    row.appendChild(fieldSelect);
    row.appendChild(opSelect);
    row.appendChild(valInput);
    row.appendChild(removeBtn);
    container.appendChild(row);
}

document.getElementById('add-condition-btn')?.addEventListener('click', function() {
    addConditionRow();
});

document.getElementById('close-rule-modal')?.addEventListener('click', function() {
    document.getElementById('rule-modal').classList.add('hidden');
});
document.getElementById('cancel-rule-btn')?.addEventListener('click', function() {
    document.getElementById('rule-modal').classList.add('hidden');
});
document.getElementById('rule-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const ruleId = this.dataset.ruleId;
    const name = document.getElementById('rule-name').value.trim();
    if (!name) {
        showToast('Rule name is required.', 'warning');
        return;
    }
    const severity = document.getElementById('rule-severity').value;
    const confidence = parseInt(document.getElementById('rule-confidence').value) || 85;
    const cooldown = parseInt(document.getElementById('rule-cooldown').value) || 60;
    const category = document.getElementById('rule-category').value;
    const mitre = document.getElementById('rule-mitre').value.trim();
    const message = document.getElementById('rule-message').value.trim() || 'Rule matched';
    const matchMode = document.getElementById('rule-match-mode').value;
    const enabled = document.getElementById('rule-enabled').checked;

    const actions = {
        alert: true,
        block_ip: document.getElementById('action-block-ip').checked,
        quarantine_host: document.getElementById('action-quarantine').checked,
        add_ioc: document.getElementById('action-add-ioc').checked,
    };

    
    const conditionRows = document.querySelectorAll('#conditions-container .condition-row');
    const conditions = [];
    let valid = true;
    conditionRows.forEach(row => {
        const field = row.querySelector('select:first-of-type').value;
        const operator = row.querySelector('select:nth-of-type(2)').value;
        const value = row.querySelector('input').value.trim();
        if (field && operator && value) {
            conditions.push({ field, operator, value });
        } else {
            valid = false;
        }
    });
    if (!valid || conditions.length === 0) {
        showToast('Each condition must have a field, operator, and value.', 'warning');
        return;
    }

    
    const validation = validateRule(conditions);
    if (!validation.valid) {
        showToast(validation.message, 'warning');
        return;
    }

    if (ruleId) {
        updateRule(parseInt(ruleId), { name, severity, confidence, cooldown, category, mitre, message, conditions, matchMode, enabled, actions });
        showToast('Rule updated.', 'success');
    } else {
        addRule(name, severity, message, conditions, enabled, confidence, actions, matchMode, category, mitre, cooldown);
        showToast('Rule added.', 'success');
    }
    document.getElementById('rule-modal').classList.add('hidden');
});

function validateRule(conditions) {
    
    const numericFields = ['src_port', 'dst_port', 'packet_size', 'entropy', 'frequency', 'risk_score'];
    const stringOperators = ['contains', 'not_contains', 'regex'];
    const numericOperators = ['gt', 'lt'];

    for (const cond of conditions) {
        const field = cond.field;
        const operator = cond.operator;
        const value = cond.value;

        
        if (numericFields.includes(field)) {
            if (stringOperators.includes(operator)) {
                return { valid: false, message: `Operator "${operator}" cannot be used with numeric field "${field}".` };
            }
            
            if (operator !== 'in' && operator !== 'not_in' && isNaN(parseFloat(value))) {
                return { valid: false, message: `Value for field "${field}" must be a number.` };
            }
        } else {
            
            if (numericOperators.includes(operator)) {
                return { valid: false, message: `Operator "${operator}" cannot be used with string field "${field}".` };
            }
            if (operator === 'regex') {
                try {
                    new RegExp(value);
                } catch (e) {
                    return { valid: false, message: `Invalid regex pattern: ${value}` };
                }
            }
        }
        
        if ((field === 'src_ip' || field === 'dst_ip') && ['eq', 'ne', 'in', 'not_in'].includes(operator)) {
            
            if (operator === 'eq' || operator === 'ne') {
                if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
                    return { valid: false, message: `Invalid IP format: ${value}` };
                }
            } else {
                
                const ips = value.split(',').map(s => s.trim());
                for (const ip of ips) {
                    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                        return { valid: false, message: `Invalid IP format in list: ${ip}` };
                    }
                }
            }
        }
        
        if ((field === 'src_port' || field === 'dst_port') && ['eq', 'ne', 'in', 'not_in', 'gt', 'lt'].includes(operator)) {
            if (operator === 'eq' || operator === 'ne' || operator === 'gt' || operator === 'lt') {
                const port = parseInt(value);
                if (isNaN(port) || port < 0 || port > 65535) {
                    return { valid: false, message: `Port must be between 0 and 65535.` };
                }
            } else {
                const ports = value.split(',').map(s => parseInt(s.trim()));
                for (const p of ports) {
                    if (isNaN(p) || p < 0 || p > 65535) {
                        return { valid: false, message: `Port must be between 0 and 65535.` };
                    }
                }
            }
        }
    }
    return { valid: true };
}
function evaluateRule(rule, packet) {
    const conditions = rule.conditions;
    const matchMode = rule.matchMode || 'AND';
    let results = [];

    for (const cond of conditions) {
        const field = cond.field;
        const operator = cond.operator;
        const expected = cond.value;
        let actual = null;

        
        switch (field) {
            case 'src_ip': actual = packet.src; break;
            case 'dst_ip': actual = packet.dst; break;
            case 'protocol': actual = packet.proto; break;
            case 'src_port': actual = packet.src_port; break;
            case 'dst_port': actual = packet.dst_port; break;
            case 'payload': actual = packet.payload || ''; break;
            case 'country_src': {
                const geo = geoCache.get(packet.src);
                actual = geo ? geo.code : 'UNK';
                break;
            }
            case 'country_dst': {
                const geo = geoCache.get(packet.dst);
                actual = geo ? geo.code : 'UNK';
                break;
            }
            case 'packet_size': actual = packet.size || 0; break;
            case 'entropy': actual = calculateEntropy(packet.payload || ''); break;
            case 'frequency': {
                
                
                const count = globalPacketData.filter(p => p.src === packet.src && p.dst === packet.dst).length;
                actual = count;
                break;
            }
            case 'risk_score': actual = packet.host_score || 0; break;
            default: actual = null;
        }

        
        if (actual === null) {
            results.push(false);
            if (matchMode === 'AND') break; 
            continue;
        }

        
        const actualStr = String(actual);
        const expectedStr = String(expected);
        let match = false;

        switch (operator) {
            case 'eq': match = actualStr === expectedStr; break;
            case 'ne': match = actualStr !== expectedStr; break;
            case 'contains': match = actualStr.includes(expectedStr); break;
            case 'not_contains': match = !actualStr.includes(expectedStr); break;
            case 'gt': match = parseFloat(actualStr) > parseFloat(expectedStr); break;
            case 'lt': match = parseFloat(actualStr) < parseFloat(expectedStr); break;
            case 'in': {
                const values = expectedStr.split(',').map(s => s.trim());
                match = values.includes(actualStr);
                break;
            }
            case 'not_in': {
                const values = expectedStr.split(',').map(s => s.trim());
                match = !values.includes(actualStr);
                break;
            }
            case 'regex': {
                try {
                    const regex = new RegExp(expectedStr, 'i');
                    match = regex.test(actualStr);
                } catch (e) {
                    match = false;
                }
                break;
            }
            default: match = false;
        }
        results.push(match);
        if (matchMode === 'AND' && !match) break; 
        if (matchMode === 'OR' && match) break;
    }

    if (matchMode === 'AND') {
        return results.every(r => r === true);
    } else { 
        return results.some(r => r === true);
    }
}
function matchRules() {
    if (rules.length === 0) return;
    const enabledRules = rules.filter(r => r.enabled);
    if (enabledRules.length === 0) return;

    for (const pkt of globalPacketData) {
        for (const rule of enabledRules) {
            const key = `rule_${rule.id}`;
            if (!shouldAlert(key, rule.cooldown || 60)) continue;

            if (evaluateRule(rule, pkt)) {
                rule.hits = (rule.hits || 0) + 1;
                rule.lastMatched = Date.now();
                saveRules();

                const mitreInfo = rule.mitre ? ` (${MITRE_INFO[rule.mitre] || rule.mitre})` : '';

               const evidence = {
                    ruleId: rule.id,
                    ruleName: rule.name,
                    conditions: rule.conditions.map(c => `${c.field} ${c.operator} ${c.value}`).join(' AND '),
                    mitre: rule.mitre || null
                };

                addTimelineEvent(
                    `Custom Rule Match: ${rule.name}`,
                    rule.severity || 'medium',
                    `${rule.message} (${evidence.conditions})${mitreInfo}`,
                    pkt.src, pkt.dst,
                    { ruleId: rule.id, ruleName: rule.name, mitre: rule.mitre },
                    rule.confidence || 85,
                    'Rule',
                    null,
                    evidence
                );

                if (rule.actions?.block_ip) {
                    blockedIPs.add(pkt.src);
                    sendBlockedIPsToBackend();
                    addTimelineEvent('Auto-Block', 'medium', `Blocked ${pkt.src} due to rule ${rule.name}`, pkt.src, pkt.dst, { ruleId: rule.id, ruleName: rule.name }, rule.confidence || 85, 'Automation');
                }
                if (rule.actions?.add_ioc) {
                    if (pkt.src && !iocs.some(i => i.value === pkt.src && i.type === 'ip')) {
                        addIOC('ip', pkt.src, `Auto-added from rule ${rule.name}`, rule.severity, null, false);
                    }
                }

                break; 
            }
        }
    }
}

function updateTopIOCWidget() {
    const container = document.getElementById('top-ioc-list');
    if (!container) return;
    const sorted = iocs.slice().sort((a, b) => (b.matchCount || 0) - (a.matchCount || 0)).slice(0, 5);
    if (sorted.length === 0) {
        container.textContent = 'No IOC hits yet.';
        return;
    }
    container.innerHTML = sorted.map(ioc => {
        const count = ioc.matchCount || 0;
        return `<div><code>${ioc.value}</code> <span style="color:var(--primary);font-weight:bold;">${count}</span> hit${count !== 1 ? 's' : ''}</div>`;
    }).join('');
}

document.getElementById('export-ioc-report')?.addEventListener('click', function() {
    const report = iocs.map(ioc => ({
        id: ioc.id,
        type: ioc.type,
        value: ioc.value,
        severity: ioc.severity,
        hits: ioc.matchCount || 0,
        firstSeen: ioc.firstSeen ? new Date(ioc.firstSeen).toISOString() : null,
        lastSeen: ioc.lastSeen ? new Date(ioc.lastSeen).toISOString() : null,
        affectedHosts: ioc.hits ? [...new Set(ioc.hits.flatMap(h => [h.src, h.dst]))].filter(Boolean) : [],
        alertIds: ioc.alertIds || [],
        description: ioc.description,
        autoBlock: ioc.autoBlock,
        expiresAt: ioc.expiresAt ? new Date(ioc.expiresAt).toISOString() : null,
        addedAt: new Date(ioc.addedAt).toISOString()
    }));
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ioc_report_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('IOC report exported.', 'success');
});

function loadResponsePolicies() {
    try {
        const stored = localStorage.getItem('neoShieldResponsePolicies');
        if (stored) {
            responsePolicies = JSON.parse(stored);
            responsePolicies = responsePolicies.map(p => ({
          ...p,
          simulateOnly: p.simulateOnly || false,
          executionCount: p.executionCount || 0,
          lastTriggered: p.lastTriggered || null
          }));
            nextPolicyId = responsePolicies.reduce((max, p) => Math.max(max, p.id), 0) + 1;
        } else {
            responsePolicies = [];
            nextPolicyId = 1;
        }
    } catch (e) {
        responsePolicies = [];
        nextPolicyId = 1;
    }
}

function saveResponsePolicies() {
    localStorage.setItem('neoShieldResponsePolicies', JSON.stringify(responsePolicies));
}

function loadActionLogs() {
    try {
        const stored = localStorage.getItem('neoShieldActionLogs');
        actionLogs = stored ? JSON.parse(stored) : [];
        nextLogId = actionLogs.reduce((max, l) => Math.max(max, l.id), 0) + 1;
    } catch (e) {
        actionLogs = [];
        nextLogId = 1;
    }
}

function saveActionLogs() {
    localStorage.setItem('neoShieldActionLogs', JSON.stringify(actionLogs));
}

function savePendingActions() {
    try {
        localStorage.setItem('neoShieldPendingActions', JSON.stringify(pendingActions));
    } catch (e) {
        console.warn('Could not save pending actions:', e);
    }
}

function loadPendingActions() {
    try {
        const stored = localStorage.getItem('neoShieldPendingActions');
        if (stored) {
            pendingActions = JSON.parse(stored);
            pendingActions = pendingActions.filter(p => p.id !== undefined);
            nextPendingId = pendingActions.reduce((max, p) => Math.max(max, p.id), 0) + 1;
        } else {
            pendingActions = [];
            nextPendingId = 1;
        }
    } catch (e) {
        pendingActions = [];
        nextPendingId = 1;
    }
}

function handleAutomatedResponse(alert) {
    if (!alert) return;
    const { confidence, severity, eventType, src, dst, id: alertId } = alert;
    const sortedPolicies = [...responsePolicies].sort((a, b) => (a.priority || 2) - (b.priority || 2));

    for (const policy of sortedPolicies) {  
        if (!policy.enabled) continue;

        const cond = policy.conditions;
        if (confidence < cond.confidenceMin || confidence > cond.confidenceMax) continue;
        if (!cond.severities.includes(severity)) continue;
        if (cond.eventTypes.length > 0 && !cond.eventTypes.includes(eventType)) continue;

        const target = src || dst || 'global';
        const cooldownKey = `autoaction_${policy.id}_${target}`;
        if (!shouldAlert(cooldownKey, policy.cooldown || 60)) continue;

        policy.executionCount = (policy.executionCount || 0) + 1;
        policy.lastTriggered = Date.now();
        saveResponsePolicies();   

        
        for (const action of policy.actions) {
            executeAction(action, alert, policy);
        }
    }
}

function executeAction(actionDef, alert, policy) {
    if (!policy.autoExecute) {
        const pending = {
            id: nextPendingId++,
            actionDef: actionDef,
            alert: alert,
            policy: policy,
            timestamp: Date.now()
        };
        pendingActions.push(pending);
        savePendingActions();
        renderApprovalQueue();

        const logEntry = {
            id: nextLogId++,
            policyId: policy.id,
            policyName: policy.name,
            actionType: actionDef.type,
            target: null,
            timestamp: Date.now(),
            success: false,
            message: 'Pending manual approval',
            autoExecute: false,
            approved: false,
            alertId: alert.id,
            severity: alert.severity,
            confidence: alert.confidence,
            undoAction: null,
            simulated: false
        };
        actionLogs.push(logEntry);
        saveActionLogs();
        renderActionLogs();
        updateActionStats();
        rebuildIndices();
        return;
    }

    const result = performAction(actionDef, alert, policy);

    const logEntry = {
        id: nextLogId++,
        policyId: policy.id,
        policyName: policy.name,
        actionType: actionDef.type,
        target: result.target || null,
        timestamp: Date.now(),
        success: result.success,
        message: result.message || 'Action executed',
        autoExecute: true,
        approved: true,
        alertId: alert.id,
        severity: alert.severity,
        confidence: alert.confidence,
        undoAction: result.undoAction || null,
        simulated: result.simulated || false
    };

    actionLogs.push(logEntry);
    saveActionLogs();
    renderActionLogs();
    updateActionStats();

    if (!result.success) {
        showToast(`Action ${actionDef.type} failed: ${result.message}`, 'danger');
    }
}

function renderPoliciesTable() {
    const tbody = document.getElementById('policy-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (responsePolicies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;">No policies defined.</td></tr>';
        return;
    }
    responsePolicies.slice().reverse().forEach(p => {
        const row = document.createElement('tr');
        const statusClass = p.enabled ? 'status-resolved' : 'status-fp';
        const statusLabel = p.enabled ? 'Enabled' : 'Disabled';
        const autoLabel = p.autoExecute ? '✅' : '🔒';
        const condStr = `Conf ${p.conditions.confidenceMin}-${p.conditions.confidenceMax}, Sev: ${p.conditions.severities.join(',')}`;
        const actionsStr = p.actions.map(a => a.type).join(', ');
        row.innerHTML = `
            <td><strong>${p.name}</strong></td>
            <td>${condStr}</td>
            <td>${actionsStr}</td>
            <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
            <td>${autoLabel}</td>
            <td>${p.executionCount || 0}</td>   <!-- hits -->
            <td>${p.lastTriggered ? new Date(p.lastTriggered).toLocaleString() : '—'}</td>
            <td>
                <button class="btn-action edit-policy" data-id="${p.id}">Edit</button>
                <button class="btn-action delete-policy" data-id="${p.id}" style="background:#ef4444;color:white;">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
    tbody.querySelectorAll('.edit-policy').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            openPolicyModal(id);
        });
    });
    tbody.querySelectorAll('.delete-policy').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            showConfirmModal('Delete Policy', 'Delete this response policy?', () => {
                responsePolicies = responsePolicies.filter(p => p.id !== id);
                saveResponsePolicies();
                renderPoliciesTable();
                showToast('Policy deleted.', 'success');
            });
        });
    });
}

function renderApprovalQueue() {
    const container = document.getElementById('approval-queue-grid');
    const badge = document.getElementById('pending-count');
    if (!container) return;

    if (pendingActions.length === 0) {
        container.innerHTML = '<div class="text-muted" style="padding: 20px; text-align: center;">No pending actions awaiting approval.</div>';
        if (badge) badge.textContent = '0';
        return;
    }

    if (badge) badge.textContent = pendingActions.length;

    let html = '';
    pendingActions.forEach(pending => {
        const actionType = pending.actionDef.type.replace(/_/g, ' ').toUpperCase();
        const target = pending.actionDef.parameters.targetIp || pending.actionDef.parameters.targetHost || '—';
        const severity = pending.alert.severity || 'medium';
        const time = new Date(pending.timestamp).toLocaleString();

        html += `
            <div class="approval-card" data-id="${pending.id}">
                <div class="card-header">
                    <span class="action-type"><i class="fas fa-play"></i> ${actionType}</span>
                    <span class="severity-${severity}">${severity.toUpperCase()}</span>
                </div>
                <div class="card-body">
                    <div><strong>Target:</strong> <span class="target">${target}</span></div>
                    <div><strong>Alert:</strong> ${pending.alert.eventType} (${pending.alert.details})</div>
                    <div><strong>Policy:</strong> ${pending.policy.name}</div>
                    <div><strong>Requested:</strong> ${time}</div>
                </div>
                <div class="card-actions">
                    <button class="btn-success btn-sm approve-btn" data-id="${pending.id}"><i class="fas fa-check"></i> Approve</button>
                    <button class="btn-danger btn-sm reject-btn" data-id="${pending.id}"><i class="fas fa-times"></i> Reject</button>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;

    
    container.querySelectorAll('.approve-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            approvePendingAction(id);
        });
    });

    container.querySelectorAll('.reject-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            rejectPendingAction(id);
        });
    });
}

function performAction(actionDef, alert, policy) {
    const { type, parameters } = actionDef;
    let result = {
        success: false,
        target: null,
        message: '',
        undoAction: null,
        simulated: false
    };

    
    if (policy.simulateOnly) {
        result.success = true;
        result.simulated = true;
        result.target = parameters.targetIp || parameters.targetHost || alert.src || 'unknown';
        result.message = `[SIMULATED] Would have executed ${type} on ${result.target}`;
        return result;
    }

    
    try {
        switch (type) {
            case 'block_ip': {
                const ip = parameters.targetIp || alert.src;
                if (ip) {
                    if (!blockedIPs.has(ip)) {
                        blockedIPs.add(ip);
                        sendBlockedIPsToBackend();
                        result.success = true;
                        result.target = ip;
                        result.message = `Blocked IP ${ip}`;
                        result.undoAction = { type: 'unblock_ip', target: ip };
                        addTimelineEvent('Auto-Block', 'medium', `Blocked ${ip} via policy ${policy.name}`, null, null, { _automated: true }, 95, 'Automation');
                    } else {
                        result.message = `IP ${ip} already blocked`;
                    }
                }
                break;
            }
            case 'quarantine_host': {
                const host = parameters.targetHost || alert.src;
                if (host && !quarantinedHosts.has(host)) {
                    quarantinedHosts.add(host);
                    result.success = true;
                    result.target = host;
                    result.message = `Quarantined host ${host}`;
                    result.undoAction = { type: 'unquarantine_host', target: host };
                    addTimelineEvent('Host Quarantine', 'critical', `Host ${host} quarantined by policy ${policy.name}`, host, null, { _automated: true }, 98, 'Automation');
                } else {
                    result.message = `Host ${host} already quarantined`;
                }
                break;
            }
            case 'add_ioc': {
                const value = parameters.iocValue || alert.src;
                const typeIoc = parameters.iocType || 'ip';
                if (value && !iocs.some(i => i.value === value && i.type === typeIoc)) {
                    addIOC(typeIoc, value, `Auto-added from policy ${policy.name} (${alert.eventType})`, 'high', null, false);
                    result.success = true;
                    result.target = value;
                    result.message = `Added IOC ${value} (${typeIoc})`;
                    
                } else {
                    result.message = `IOC ${value} already exists`;
                }
                break;
            }
            case 'create_case': {
                const title = parameters.caseTitle || `Auto-case: ${alert.eventType}`;
                const newCase = createCase({
                    title: title,
                    severity: alert.severity,
                    status: 'open',
                    assignedTo: null,
                    description: `Automated case from policy ${policy.name}\nAlert: ${alert.details}`,
                    alerts: [alert.id],
                    evidence: [{ type: 'alert', id: alert.id }],
                });
                result.success = true;
                result.target = newCase.id;
                result.message = `Created case #${newCase.id}`;
                break;
            }
            case 'send_notification': {
                const channel = parameters.channel || 'dashboard';
                showToast(`🔔 [${channel}] ${alert.details}`, 'warning');
                result.success = true;
                result.target = channel;
                result.message = `Notification sent to ${channel}`;
                break;
            }
            case 'raise_severity': {
                const newSev = parameters.newSeverity || 'critical';
                const oldSev = alert.severity;
                if (newSev !== oldSev && ['low', 'medium', 'high', 'critical'].includes(newSev)) {
                    alert.severity = newSev;
                    result.success = true;
                    result.target = newSev;
                    result.message = `Alert severity raised from ${oldSev} to ${newSev}`;
                } else {
                    result.message = `Severity unchanged (${oldSev})`;
                }
                break;
            }
            case 'kill_connection': {
                result.success = true;
                result.target = `${alert.src} → ${alert.dst}`;
                result.message = `Killed connection ${alert.src} → ${alert.dst}`;
                break;
            }
            default:
                result.message = `Unknown action type: ${type}`;
        }
    } catch (error) {
        result.message = `Error: ${error.message}`;
        console.error('Action execution error:', error);
    }

    return result;
}

function approvePendingAction(pendingId) {
    const idx = pendingActions.findIndex(p => p.id === pendingId);
    if (idx === -1) {
        showToast('Pending action not found.', 'danger');
        return;
    }
    const pending = pendingActions[idx];

    const result = performAction(pending.actionDef, pending.alert, pending.policy);

    const log = actionLogs.find(l =>
        l.alertId === pending.alert.id &&
        l.actionType === pending.actionDef.type &&
        l.success === false &&
        l.approved === false
    );
    if (log) {
        log.success = result.success;
        log.approved = true;
        log.target = result.target || log.target;
        log.message = result.message || 'Approved manually';
        log.undoAction = result.undoAction || null;
        log.simulated = result.simulated || false;
        saveActionLogs();
    } else {
        const newLog = {
            id: nextLogId++,
            policyId: pending.policy.id,
            policyName: pending.policy.name,
            actionType: pending.actionDef.type,
            target: result.target || null,
            timestamp: Date.now(),
            success: result.success,
            message: result.message || 'Approved and executed',
            autoExecute: false,
            approved: true,
            alertId: pending.alert.id,
            severity: pending.alert.severity,
            confidence: pending.alert.confidence,
            undoAction: result.undoAction || null,
            simulated: result.simulated || false
        };
        actionLogs.push(newLog);
        saveActionLogs();
    }

    pendingActions.splice(idx, 1);
    savePendingActions();
    renderApprovalQueue();
    renderActionLogs();
    updateActionStats();

    showToast(`Action ${pending.actionDef.type} approved and executed.`, 'success');
}

function rejectPendingAction(pendingId) {
    const idx = pendingActions.findIndex(p => p.id === pendingId);
    if (idx === -1) return;
    const pending = pendingActions[idx];

    const log = actionLogs.find(l =>
        l.alertId === pending.alert.id &&
        l.actionType === pending.actionDef.type &&
        l.success === false &&
        l.approved === false
    );
    if (log) {
        log.message = 'Rejected by analyst';
        log.approved = false; 
        log.rejected = true;
        saveActionLogs();
    }

    pendingActions.splice(idx, 1);
    savePendingActions();
    renderApprovalQueue();
    renderActionLogs();
    updateActionStats();

    showToast('Action rejected.', 'warning');
}

function rollbackAction(logId) {
    const log = actionLogs.find(l => l.id === logId);
    if (!log) {
        showToast('Log entry not found.', 'danger');
        return;
    }
    if (!log.undoAction) {
        showToast('This action does not support rollback.', 'warning');
        return;
    }
    if (!log.success) {
        showToast('Cannot rollback a failed action.', 'warning');
        return;
    }
    if (log.rolledBack) {
        showToast('Action already rolled back.', 'info');
        return;
    }

    const undo = log.undoAction;
    let rollbackSuccess = false;
    let rollbackMessage = '';

    try {
        switch (undo.type) {
            case 'unblock_ip': {
                const ip = undo.target;
                if (blockedIPs.has(ip)) {
                    blockedIPs.delete(ip);
                    sendUnblockedIPsToBackend();
                    rollbackSuccess = true;
                    rollbackMessage = `Unblocked IP ${ip}`;
                    addTimelineEvent('Rollback', 'low', `Rollback: unblocked ${ip} (was ${log.actionType})`, null, null, { _automated: true }, 100, 'System');
                } else {
                    rollbackMessage = `IP ${ip} was not blocked (already unblocked)`;
                    rollbackSuccess = true;
                }
                break;
            }
            case 'unquarantine_host': {
                const host = undo.target;
                if (quarantinedHosts.has(host)) {
                    quarantinedHosts.delete(host);
                    rollbackSuccess = true;
                    rollbackMessage = `Unquarantined host ${host}`;
                    addTimelineEvent('Rollback', 'low', `Rollback: unquarantined ${host} (was ${log.actionType})`, host, null, { _automated: true }, 100);
                } else {
                    rollbackMessage = `Host ${host} was not quarantined`;
                    rollbackSuccess = true;
                }
                break;
            }
            case 'delete_ioc': {
                const iocValue = undo.target;
                const iocType = undo.iocType || 'ip'; 
                const iocIndex = iocs.findIndex(i => i.value === iocValue && i.type === iocType);
                if (iocIndex !== -1) {
                    const removed = iocs.splice(iocIndex, 1)[0];
                    saveIOCs();
                    renderIOCs();
                    rollbackSuccess = true;
                    rollbackMessage = `Removed IOC ${iocValue} (${iocType})`;
                    addTimelineEvent('Rollback', 'low', `Rollback: removed IOC ${iocValue}`, null, null, { _automated: true }, 100);
                } else {
                    rollbackMessage = `IOC ${iocValue} not found`;
                    rollbackSuccess = true;
                }
                break;
            }
            case 'revert_severity': {
                const originalSeverity = undo.originalSeverity;
                if (originalSeverity && log.alertId) {
                    const alert = timelineEvents.find(e => e.id === log.alertId);
                    if (alert) {
                        alert.severity = originalSeverity;
                        rollbackSuccess = true;
                        rollbackMessage = `Reverted alert severity to ${originalSeverity}`;
                        renderTimeline();
                        renderAlertsTable();
                    } else {
                        rollbackMessage = 'Alert not found';
                        rollbackSuccess = false;
                    }
                } else {
                    rollbackMessage = 'Missing original severity info';
                    rollbackSuccess = false;
                }
                break;
            }
            case 'close_case': {
                const caseId = undo.target;
                const caseObj = cases.find(c => c.id === caseId);
                if (caseObj && caseObj.status !== 'resolved') {
                    caseObj.status = 'resolved';
                    caseObj.closedAt = Date.now();
                    caseObj.notes.push({ timestamp: Date.now(), text: `Case closed via rollback of ${log.actionType}` });
                    saveCases();
                    renderCasesTable();
                    rollbackSuccess = true;
                    rollbackMessage = `Closed case #${caseId}`;
                    addTimelineEvent('Rollback', 'low', `Rollback: closed case #${caseId}`, null, null, { _automated: true }, 100);
                } else {
                    rollbackMessage = caseObj ? 'Case already closed' : 'Case not found';
                    rollbackSuccess = true; 
                }
                break;
            }
            default:
                rollbackMessage = `Rollback not implemented for ${undo.type}`;
                rollbackSuccess = false;
        }
    } catch (error) {
        rollbackSuccess = false;
        rollbackMessage = `Rollback error: ${error.message}`;
        console.error('Rollback error:', error);
    }

    if (rollbackSuccess) {
        log.rolledBack = true;
        saveActionLogs();

        const rollbackLog = {
            id: nextLogId++,
            policyId: log.policyId,
            policyName: log.policyName,
            actionType: 'rollback',
            target: undo.target || null,
            timestamp: Date.now(),
            success: true,
            message: rollbackMessage,
            autoExecute: false,
            approved: true,
            alertId: log.alertId,
            severity: log.severity,
            confidence: log.confidence,
            undoAction: null, 
            simulated: false,
            rolledBack: false
        };
        actionLogs.push(rollbackLog);
        saveActionLogs();
        renderActionLogs();
        updateActionStats();
        showToast(rollbackMessage, 'success');
    } else {
        showToast(`Rollback failed: ${rollbackMessage}`, 'danger');
    }
}

function addHighlightedActionLog(actionType, target, message) {
    const logEntry = {
        id: nextLogId++,
        policyId: null,
        policyName: 'Manual Action',
        actionType: actionType,
        target: target,
        timestamp: Date.now(),
        success: true,
        message: message || 'Manual action executed',
        autoExecute: false,
        approved: true,
        alertId: currentInvestigationAlertId || null,
        severity: 'high',
        confidence: 100,
        undoAction: null,
        simulated: false,
        highlighted: true,         
        undoAction: (actionType === 'block_ip') ? { type: 'unblock_ip', target: target } :
        (actionType === 'quarantine_host') ? { type: 'unquarantine_host', target: target } :
        null

    };
    
    actionLogs.push(logEntry);
    saveActionLogs();
    renderActionLogs();
    updateActionStats();
    rebuildIndices();
}



function renderActionLogs() {
    const tbody = document.getElementById('action-log-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (actionLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No actions logged.</td></tr>';
        return;
    }
    const logs = actionLogs.slice().reverse().slice(0, 50);
    logs.forEach(log => {
        const row = document.createElement('tr');
        if (log.highlighted) {
            row.classList.add('highlighted-log-row');
        }
        const statusClass = log.success ? 'status-resolved' : (log.approved === false ? 'status-fp' : 'status-open');
        let statusText = log.success ? '✅ Executed' : (log.approved === false ? '⏳ Pending' : '❌ Failed');
        if (log.simulated) statusText = '🔬 Simulated';
        let actionsHtml = '';
        if (!log.success && log.approved === false) {
            actionsHtml = `<button class="btn-action approve-action" data-id="${log.id}">Approve</button>`;
        }
        let rollbackHtml = '';
        if (log.success && log.undoAction && !log.rolledBack) {
            rollbackHtml = `<button class="btn-action rollback" data-log-id="${log.id}">↩ Rollback</button>`;
        }
        row.innerHTML = `
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td>${log.policyName || '—'}</td>
            <td>${log.actionType}</td>
            <td>${log.target || '—'}</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>${log.message} ${actionsHtml} ${rollbackHtml}</td>
        `;
        tbody.appendChild(row);
    });

    tbody.querySelectorAll('.approve-action').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const logId = parseInt(this.dataset.id);
            const log = actionLogs.find(l => l.id === logId);
            if (!log) return;
            log.approved = true;
            log.success = true;
            log.message = 'Approved manually.';
            saveActionLogs();
            renderActionLogs();
            updateActionStats();
            showToast('Action approved.', 'success');
        });
    });

    tbody.querySelectorAll('.rollback').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const logId = parseInt(this.dataset.logId);
            rollbackAction(logId);
        });
    });
}

function createPolicyFromLastAction() {
    if (!lastManualAction) {
        showToast('No manual action recorded to base a policy on.', 'warning');
        return;
    }
    const { type, target, params } = lastManualAction;
    let template = {
        name: `Auto-block ${target}`,
        desc: `Policy created from manual action: ${type} on ${target}`,
        conditions: {
            confidenceMin: 50,
            confidenceMax: 100,
            severities: ['high', 'critical'],
            eventTypes: []
        },
        actions: [
            { type: type, parameters: params }
        ],
        priority: 1,
        autoExecute: true,
        simulateOnly: false
    };
    if (type === 'block_ip') {
        template.name = `Block IP ${target}`;
        template.actions = [{ type: 'block_ip', parameters: { targetIp: target } }];
    } else if (type === 'quarantine_host') {
        template.name = `Quarantine Host ${target}`;
        template.actions = [{ type: 'quarantine_host', parameters: { targetHost: target } }];
    }
    openPolicyModal(null, template);
}

function updateActionStats() {
    const total = actionLogs.length;
    const success = actionLogs.filter(l => l.success).length;
    const pending = actionLogs.filter(l => l.approved === false && !l.success).length;
    document.getElementById('auto-total-actions').textContent = total;
    document.getElementById('auto-success-actions').textContent = success;
    document.getElementById('auto-pending-actions').textContent = pending;
    document.getElementById('auto-blocked-hosts').textContent = blockedIPs.size;
    renderAutoTimeline();
}

function openPolicyModal(policyId = null, template = null) {
    const modal = document.getElementById('policy-modal');
    const title = document.getElementById('policy-modal-title');
    const form = document.getElementById('policy-form');
    const container = document.getElementById('policy-actions-container');
    container.innerHTML = '';

    
    document.getElementById('policy-name').value = '';
    document.getElementById('policy-description').value = '';
    document.getElementById('policy-conf-min').value = 0;
    document.getElementById('policy-conf-max').value = 100;
    document.querySelectorAll('.policy-sev').forEach(cb => cb.checked = true);
    document.getElementById('policy-event-types').value = '';
    document.getElementById('policy-cooldown').value = 300;
    document.getElementById('policy-expires').value = 3600;
    document.getElementById('policy-auto-execute').checked = true;
    document.getElementById('policy-enabled').checked = true;
    document.getElementById('policy-priority').value = 2;
    document.getElementById('policy-simulate-only').checked = false;
    form.dataset.policyId = '';

    if (policyId) {
        
        const policy = responsePolicies.find(p => p.id === policyId);
        if (!policy) return;
        title.textContent = 'Edit Policy';
        
        document.getElementById('policy-name').value = policy.name;
        document.getElementById('policy-description').value = policy.description || '';
        document.getElementById('policy-conf-min').value = policy.conditions.confidenceMin;
        document.getElementById('policy-conf-max').value = policy.conditions.confidenceMax;
        document.querySelectorAll('.policy-sev').forEach(cb => {
            cb.checked = policy.conditions.severities.includes(cb.value);
        });
        document.getElementById('policy-event-types').value = policy.conditions.eventTypes.join(', ');
        document.getElementById('policy-cooldown').value = policy.cooldown || 300;
        document.getElementById('policy-expires').value = policy.expiresAfter || 3600;
        document.getElementById('policy-auto-execute').checked = policy.autoExecute;
        document.getElementById('policy-enabled').checked = policy.enabled;
        document.getElementById('policy-priority').value = policy.priority || 2;
        document.getElementById('policy-simulate-only').checked = policy.simulateOnly || false;
        
        policy.actions.forEach(a => addActionRow(a.type, a.parameters));
        form.dataset.policyId = policyId;
        title.textContent = 'Edit Policy';
    } else if (template) {
        
        title.textContent = 'New Policy from Template';
        document.getElementById('policy-name').value = template.name;
        document.getElementById('policy-description').value = template.desc;
        document.getElementById('policy-conf-min').value = template.conditions.confidenceMin;
        document.getElementById('policy-conf-max').value = template.conditions.confidenceMax;
        
        document.querySelectorAll('.policy-sev').forEach(cb => {
            cb.checked = template.conditions.severities.includes(cb.value);
        });
        document.getElementById('policy-event-types').value = template.conditions.eventTypes.join(', ');
        document.getElementById('policy-priority').value = template.priority || 2;
        document.getElementById('policy-auto-execute').checked = template.autoExecute !== undefined ? template.autoExecute : true;
        document.getElementById('policy-simulate-only').checked = template.simulateOnly || false;
        
        template.actions.forEach(a => addActionRow(a.type, a.parameters));
        form.dataset.policyId = '';
    } else {
        
        title.textContent = 'New Policy';
        
        addActionRow('block_ip', { targetIp: '{{src}}' });
    }

    modal.classList.remove('hidden');
}

function addActionRow(type = 'block_ip', params = {}) {
    const container = document.getElementById('policy-actions-container');
    const row = document.createElement('div');
    row.className = 'action-row';
    row.style.display = 'flex';
    row.style.gap = '8px';
    row.style.marginBottom = '8px';
    row.style.alignItems = 'center';

    
    const typeSelect = document.createElement('select');
    typeSelect.className = 'modal-select';
    typeSelect.style.flex = '1';
    ACTION_TYPES.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t.replace(/_/g, ' ').toUpperCase();
        if (t === type) opt.selected = true;
        typeSelect.appendChild(opt);
    });

    
    const paramInput = document.createElement('input');
    paramInput.type = 'text';
    paramInput.className = 'modal-input';
    paramInput.placeholder = '{"targetIp":"{{src}}"}';
    paramInput.style.flex = '2';
    paramInput.value = JSON.stringify(params);

    
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn-action';
    removeBtn.style.background = '#ef4444';
    removeBtn.style.color = 'white';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', function() {
        if (container.children.length > 1) {
            container.removeChild(row);
        } else {
            showToast('At least one action is required.', 'warning');
        }
    });

    row.appendChild(typeSelect);
    row.appendChild(paramInput);
    row.appendChild(removeBtn);
    container.appendChild(row);
}

document.getElementById('policy-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const policyId = this.dataset.policyId;
    const name = document.getElementById('policy-name').value.trim();
    if (!name) {
        showToast('Policy name is required.', 'warning');
        return;
    }
    const description = document.getElementById('policy-description').value.trim();
    const confMin = parseInt(document.getElementById('policy-conf-min').value) || 0;
    const confMax = parseInt(document.getElementById('policy-conf-max').value) || 100;
    const severities = Array.from(document.querySelectorAll('.policy-sev:checked')).map(cb => cb.value);
    const eventTypes = document.getElementById('policy-event-types').value.split(',').map(s => s.trim()).filter(Boolean);
    const cooldown = parseInt(document.getElementById('policy-cooldown').value) || 300;
    const expiresAfter = parseInt(document.getElementById('policy-expires').value) || 0;
    const autoExecute = document.getElementById('policy-auto-execute').checked;
    const simulateOnly = document.getElementById('policy-simulate-only').checked;
    const enabled = document.getElementById('policy-enabled').checked;
    const priority = parseInt(document.getElementById('policy-priority').value) || 2;

    
    const actionRows = document.querySelectorAll('#policy-actions-container .action-row');
    const actions = [];
    actionRows.forEach(row => {
        const type = row.querySelector('select').value;
        const paramsText = row.querySelector('input').value.trim();
        let params = {};
        try {
            params = JSON.parse(paramsText || '{}');
        } catch (e) {
            showToast('Invalid JSON in action parameters.', 'warning');
            return;
        }
        actions.push({ type, parameters: params });
    });
    if (actions.length === 0) {
        showToast('At least one action is required.', 'warning');
        return;
    }

    const policy = {
        id: policyId ? parseInt(policyId) : nextPolicyId++,
        name,
        description,
        enabled,
        conditions: { confidenceMin: confMin, confidenceMax: confMax, severities, eventTypes },
        actions,
        autoExecute,
        cooldown,
        expiresAfter,
        createdAt: policyId ? undefined : Date.now(),
        simulateOnly: simulateOnly,
        priority: priority,
        executionCount: 0,         
        lastTriggered: null         
    };

    if (policyId) {
        const idx = responsePolicies.findIndex(p => p.id === policy.id);
        if (idx !== -1) responsePolicies[idx] = policy;
    } else {
        responsePolicies.push(policy);
    }
    saveResponsePolicies();
    renderPoliciesTable();
    document.getElementById('policy-modal').classList.add('hidden');
    showToast(`Policy ${policyId ? 'updated' : 'created'}.`, 'success');
});

document.getElementById('add-policy-btn')?.addEventListener('click', function() {
    openPolicyModal();
});

document.getElementById('close-policy-modal')?.addEventListener('click', () => {
    document.getElementById('policy-modal').classList.add('hidden');
});
document.getElementById('cancel-policy-btn')?.addEventListener('click', () => {
    document.getElementById('policy-modal').classList.add('hidden');
});

document.getElementById('add-action-row')?.addEventListener('click', () => addActionRow());

function renderAutoTimeline() {
    const container = document.getElementById('auto-timeline');
    if (!container) return;
    const logs = actionLogs.slice().reverse().slice(0, 10);
    if (logs.length === 0) {
        container.textContent = 'No automated actions yet.';
        return;
    }
    container.innerHTML = logs.map(log => {
        const icon = log.success ? '✅' : (log.approved === false ? '⏳' : '❌');
        return `<div>${icon} ${new Date(log.timestamp).toLocaleTimeString()} - ${log.actionType} → ${log.target || 'N/A'} (${log.message})</div>`;
    }).join('');
}

function renderTemplates() {
    const container = document.getElementById('policy-templates-grid');
    if (!container) return;

    let html = '';
    POLICY_TEMPLATES.forEach((template, index) => {
        const actionList = template.actions.map(a => a.type.replace(/_/g, ' ').toUpperCase()).join(' + ');
        html += `
            <div class="template-card" data-template-index="${index}">
                <div class="template-icon">${template.icon}</div>
                <div class="template-name">${template.name}</div>
                <div class="template-desc">${template.desc}</div>
                <div class="template-actions">${actionList}</div>
            </div>
        `;
    });
    container.innerHTML = html;

    container.querySelectorAll('.template-card').forEach(card => {
        card.addEventListener('click', function() {
            const index = parseInt(this.dataset.templateIndex);
            const template = POLICY_TEMPLATES[index];
            if (template) {
                openPolicyModal(null, template);
            }
        });
    });
}

let investigationNetwork = null;
let _allGraphNodes = [];
let _allGraphEdges = [];
let selectedNodeId = null;

function buildInvestigationGraph() {
    const nodes = [];
    const edges = [];
    const nodeSet = new Set();
    const techniqueMap = new Map();

    function addNode(id, label, type, color, size = 20, extra = {}) {
        if (nodeSet.has(id)) return;
        nodeSet.add(id);
        const node = {
            id, label, type, color, size,
            font: { color: '#fff' },
            ...extra
        };
        nodes.push(node);
    }

    function addEdge(from, to, label = '', color = '#9ca3af') {
        edges.push({ from, to, label, arrows: 'to', smooth: { type: 'curvedCW', roundness: 0.1 }, color });
    }

    
    for (const [host, entry] of hostStages.entries()) {
        const risk = mlInfoMap.get(host)?.score || 0;
        const color = risk > 80 ? '#ef4444' : risk > 50 ? '#f59e0b' : '#10b981';
        const label = risk > 0 ? `${host} [${risk.toFixed(0)}]` : host;
        addNode(`host-${host}`, label, 'host', color, 25, { risk });
    }

    
    timelineEvents.slice(0, 150).forEach(ev => {
        const id = `alert-${ev.id}`;
        const color = ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f59e0b' : '#fbbf24';
        const label = ev.eventType.length > 20 ? ev.eventType.slice(0, 18) + '…' : ev.eventType;
        addNode(id, label, 'alert', color, 30, {
            details: ev.details,
            src: ev.src,
            dst: ev.dst,
            timestamp: formatAlertTime(ev),
            confidence: ev.confidence || 0,
            severity: ev.severity,
            mitre: ev.mitre
        });
        if (ev.src) {
            addNode(`host-${ev.src}`, ev.src, 'host', '#6b7280');
            const edgeColor = ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f59e0b' : '#fbbf24';
            addEdge(`host-${ev.src}`, id, 'source', edgeColor);
        }
        if (ev.dst) {
            addNode(`host-${ev.dst}`, ev.dst, 'host', '#6b7280');
            const edgeColor = ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f59e0b' : '#fbbf24';
            addEdge(`host-${ev.dst}`, id, 'dest', edgeColor);
        }
        if (ev.mitre) {
            const techId = `mitre-${ev.mitre}`;
            if (!techniqueMap.has(ev.mitre)) {
                techniqueMap.set(ev.mitre, { id: techId, label: ev.mitre, count: 0 });
            }
            techniqueMap.get(ev.mitre).count++;
        }
    });

    
    for (const [techId, info] of techniqueMap) {
        const displayName = `${techId} (${MITRE_INFO[techId] || techId})`;
        addNode(info.id, displayName, 'mitre', '#a78bfa', 35);
        
        timelineEvents.filter(ev => ev.mitre === techId).forEach(ev => {
            const alertId = `alert-${ev.id}`;
            if (nodeSet.has(alertId)) {
                addEdge(alertId, info.id, 'technique', '#a78bfa');
            }
        });
    }

    
    iocs.forEach(ioc => {
        const id = `ioc-${ioc.id}`;
        const color = ioc.severity === 'critical' ? '#ef4444' : ioc.severity === 'high' ? '#f59e0b' : '#fbbf24';
        addNode(id, ioc.value, 'ioc', color, 28, { type: ioc.type, description: ioc.description, severity: ioc.severity });
        if (ioc.hits && ioc.hits.length > 0) {
            const affected = new Set();
            ioc.hits.forEach(hit => {
                if (hit.src) affected.add(hit.src);
                if (hit.dst) affected.add(hit.dst);
            });
            affected.forEach(host => {
                addNode(`host-${host}`, host, 'host', '#6b7280');
                const edgeColor = ioc.severity === 'critical' ? '#ef4444' : ioc.severity === 'high' ? '#f59e0b' : '#fbbf24';
                addEdge(id, `host-${host}`, 'hit', edgeColor);
            });
        }
    });

    
    cases.forEach(c => {
        const id = `case-${c.id}`;
        const color = c.severity === 'critical' ? '#ef4444' : c.severity === 'high' ? '#f59e0b' : '#fbbf24';
        addNode(id, `Case #${c.id}`, 'case', color, 32, { description: c.description, status: c.status, severity: c.severity });
        if (c.alerts) {
            c.alerts.forEach(alertId => {
                const alertNode = `alert-${alertId}`;
                if (nodeSet.has(alertNode)) {
                    addEdge(alertNode, id, 'linked', '#6b7280');
                }
            });
        }
    });

    
    flowLines.forEach((flow, key) => {
        const srcNode = `host-${flow.src}`;
        const dstNode = `host-${flow.dst}`;
        if (nodeSet.has(srcNode) && nodeSet.has(dstNode)) {
            const risk = flow.riskSum / flow.count;
            const color = risk > 80 ? '#ef4444' : risk > 50 ? '#f59e0b' : '#10b981';
            addEdge(srcNode, dstNode, `${flow.count} pkts`, color);
        }
    });

    
    blockedIPs.forEach(ip => {
        if (!nodeSet.has(`host-${ip}`)) {
            addNode(`host-${ip}`, ip, 'ip', '#ef4444', 22, { blocked: true });
        }
    });

    return { nodes, edges };
}

function renderInvestigationGraph() {
    const container = document.getElementById('investigation-graph');
    if (!container) return;

    const data = buildInvestigationGraph();
    _allGraphNodes = data.nodes;
    _allGraphEdges = data.edges;

    
    
    
    let filteredNodes, filteredEdges;
    if (_allGraphNodes.length <= 50) {
        filteredNodes = _allGraphNodes;
        filteredEdges = _allGraphEdges;
    } else {
        
        const hostIds = _allGraphNodes.filter(n => n.type === 'host').map(n => n.id);
        const neighborIds = new Set(hostIds);
        _allGraphEdges.forEach(e => {
            if (hostIds.includes(e.from)) neighborIds.add(e.to);
            if (hostIds.includes(e.to)) neighborIds.add(e.from);
        });
        filteredNodes = _allGraphNodes.filter(n => neighborIds.has(n.id));
        filteredEdges = _allGraphEdges.filter(e => neighborIds.has(e.from) && neighborIds.has(e.to));
    }

    const nodes = new vis.DataSet(filteredNodes.map(n => ({
        ...n,
        title: `${n.label}\nType: ${n.type}\n${n.details ? 'Details: '+n.details : ''}`
    })));

    const edges = new vis.DataSet(filteredEdges);

    const options = {
        nodes: {
            shape: 'dot',
            size: 20,
            font: { color: '#fff', size: 12, face: 'Inter', background: 'rgba(0,0,0,0.6)' }
        },
        edges: {
            width: 1,
            font: { color: '#9ca3af', size: 10, align: 'middle', background: 'rgba(0,0,0,0.4)' }
        },
        physics: { enabled: true, stabilization: true },
        interaction: { hover: true, navigationButtons: true, tooltipDelay: 200 },
        layout: { randomSeed: 42 }
    };

    if (investigationNetwork) investigationNetwork.destroy();
    investigationNetwork = new vis.Network(container, { nodes, edges }, options);

    
    investigationNetwork.on('click', function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            selectedNodeId = nodeId;
            const nodeData = nodes.get(nodeId);
            showGraphNodeDetail(nodeData);
        } else {
            hideGraphDetail();
        }
    });

    investigationNetwork.on('doubleClick', function(params) {
        if (params.nodes.length > 0) {
            investigationNetwork.focus(params.nodes[0], { scale: 1.5, animation: true });
        }
    });

    window._graphNodes = nodes;
    window._graphEdges = edges;
}


function expandNode(nodeId) {
    if (!investigationNetwork) return;
    
    const allNodes = _allGraphNodes;
    const allEdges = _allGraphEdges;
    const visited = new Set();
    const queue = [{ id: nodeId, d: 0 }];
    while (queue.length) {
        const { id, d } = queue.shift();
        if (visited.has(id) || d > 2) continue;
        visited.add(id);
        allEdges.forEach(e => {
            if (e.from === id || e.to === id) {
                const neighbor = e.from === id ? e.to : e.from;
                if (!visited.has(neighbor)) {
                    queue.push({ id: neighbor, d: d + 1 });
                }
            }
        });
    }
    const filteredNodes = allNodes.filter(n => visited.has(n.id));
    const filteredEdges = allEdges.filter(e => visited.has(e.from) && visited.has(e.to));
    const nodes = new vis.DataSet(filteredNodes);
    const edges = new vis.DataSet(filteredEdges);
    investigationNetwork.setData({ nodes, edges });
    investigationNetwork.fit({ animation: true });

    window._graphNodes = nodes;
    window._graphEdges = edges; 
}
function showGraphNodeDetail(nodeData) {
    const panel = document.getElementById('graph-detail-panel');
    const content = document.getElementById('graph-detail-content');
    if (!content) return;

    let html = `<button class="close-panel" id="graph-close-detail">&times;</button>`;
    html += `<h4>${nodeData.label}</h4>`;
    html += `<p><strong>Type:</strong> ${nodeData.type}</p>`;
    if (nodeData.risk !== undefined) html += `<p><strong>Risk:</strong> ${nodeData.risk.toFixed(1)}</p>`;
    if (nodeData.confidence !== undefined) html += `<p><strong>Confidence:</strong> ${nodeData.confidence}%</p>`;
    if (nodeData.details) html += `<p><strong>Details:</strong> ${nodeData.details}</p>`;
    if (nodeData.description) html += `<p><strong>Description:</strong> ${nodeData.description}</p>`;
    if (nodeData.status) html += `<p><strong>Status:</strong> ${nodeData.status}</p>`;
    if (nodeData.severity) html += `<p><strong>Severity:</strong> ${nodeData.severity}</p>`;
    if (nodeData.blocked) html += `<p><strong>Blocked:</strong> Yes</p>`;
    if (nodeData.mitre) html += `<p><strong>MITRE:</strong> ${nodeData.mitre}</p>`;

    
    const relatedAlerts = timelineEvents.filter(e => e.src === nodeData.label || e.dst === nodeData.label);
    if (relatedAlerts.length) {
        html += `<p><strong>Related Alerts:</strong> ${relatedAlerts.length}</p>`;
        relatedAlerts.slice(0, 5).forEach(e => {
            html += `<div style="font-size:12px; color:var(--text-muted);">${formatAlertTime(e)} - ${e.eventType}</div>`;
        });
    }

    
    if (nodeData.type === 'host' || nodeData.type === 'ip') {
        html += `<button class="btn-primary btn-sm" id="graph-expand-neighbors" style="margin-top:12px;">Expand Neighbors</button>`;
        html += `<button class="btn-secondary btn-sm" id="graph-view-timeline" style="margin-top:12px; margin-left:8px;">View Timeline</button>`;
    }

    content.innerHTML = html;
    panel.style.display = 'block';

    document.getElementById('graph-close-detail')?.addEventListener('click', hideGraphDetail);
    document.getElementById('graph-expand-neighbors')?.addEventListener('click', function() {
        if (selectedNodeId) {
            expandNode(selectedNodeId);
            hideGraphDetail(); 
        }
    });
    document.getElementById('graph-view-timeline')?.addEventListener('click', function() {
        const ip = nodeData.label;
        viewTimelineForNode(ip);
    });
}

function hideGraphDetail() {
    const panel = document.getElementById('graph-detail-panel');
    if (panel) panel.style.display = 'none';
}

function setupGraphFilters() {
    const checkboxes = document.querySelectorAll('#graph-show-hosts, #graph-show-alerts, #graph-show-iocs, #graph-show-cases, #graph-show-ips, #graph-show-edges');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', applyGraphFilters);
    });
    document.getElementById('graph-reset-filters')?.addEventListener('click', () => {
        checkboxes.forEach(cb => cb.checked = true);
        applyGraphFilters();
    });
}

function applyGraphFilters() {
    if (!window._graphNodes || !window._graphEdges) return;
    const showHosts = document.getElementById('graph-show-hosts').checked;
    const showAlerts = document.getElementById('graph-show-alerts').checked;
    const showIOCs = document.getElementById('graph-show-iocs').checked;
    const showCases = document.getElementById('graph-show-cases').checked;
    const showIPs = document.getElementById('graph-show-ips').checked;
    const showEdges = document.getElementById('graph-show-edges').checked;
    const showMitre = document.getElementById('graph-show-mitre').checked;

    const nodeFilter = (node) => {
        if (node.type === 'host' && !showHosts) return false;
        if (node.type === 'alert' && !showAlerts) return false;
        if (node.type === 'ioc' && !showIOCs) return false;
        if (node.type === 'case' && !showCases) return false;
        if (node.type === 'ip' && !showIPs) return false;
        if (node.type === 'mitre' && !showMitre) return false;
        return true;
    };

    const allNodes = window._graphNodes;
    const allEdges = window._graphEdges;
    const visibleNodeIds = new Set();
    allNodes.forEach(node => {
        const visible = nodeFilter(node);
        allNodes.update({ id: node.id, hidden: !visible });
        if (visible) visibleNodeIds.add(node.id);
    });

    allEdges.forEach(edge => {
        const fromVisible = visibleNodeIds.has(edge.from);
        const toVisible = visibleNodeIds.has(edge.to);
        allEdges.update({ id: edge.id, hidden: !(fromVisible && toVisible && showEdges) });
    });
}

document.getElementById('graph-export')?.addEventListener('click', function() {
    if (investigationNetwork) {
        const canvas = document.querySelector('#investigation-graph canvas');
        if (canvas) {
            const link = document.createElement('a');
            link.download = 'investigation_graph.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
        }
    }
});

function viewTimelineForNode(ip) {
    const searchInput = document.getElementById('alert-search');
    if (searchInput) {
        searchInput.value = ip;
        renderAlertsTable();
    }
    switchView('alerts');
}

document.getElementById('graph-zoom-fit')?.addEventListener('click', function() {
    if (investigationNetwork) {
        investigationNetwork.fit({ animation: true });
    }
});

function forceGraphRedraw() {
    if (investigationNetwork) {
        investigationNetwork.redraw();
    }
}

function refreshGraph() {
    const container = document.getElementById('investigation-graph');
    if (!container) return;
    container.style.display = 'none';
    setTimeout(() => {
        container.style.display = 'block';
        if (investigationNetwork) {
            investigationNetwork.redraw();
        }
    }, 50);
}

window.addEventListener('resize', forceGraphRedraw);

let scrollTimeout;
document.querySelector('.main-content')?.addEventListener('scroll', function() {
    clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(forceGraphRedraw, 100);
});

let huntingResults = {
    packets: [],
    alerts: [],
    hosts: [],
    iocs: []
};

function parseHuntingQuery(query) {
    const tokens = query.trim().split(/\s+/);
    const conditions = {};
    tokens.forEach(token => {
        const parts = token.split(':');
        if (parts.length === 2) {
            const key = parts[0].toLowerCase();
            const value = parts[1];
            if (['src', 'dst', 'protocol', 'country', 'severity', 'type', 'risk', 'confidence', 'ioc', 'host', 'event', 'ip'].includes(key)) {
                if (!conditions[key]) conditions[key] = [];
                conditions[key].push(value);
            }
        }
    });
    return conditions;
}

function parseNaturalLanguageQuery(input) {
    if (!input || input.trim() === '') return { query: '', interpretation: [] };
    const lower = input.toLowerCase().trim();
    const parts = [];
    const interpretation = [];

    
    function addCondition(key, value, explanation) {
        parts.push(`${key}:${value}`);
        if (explanation) interpretation.push(explanation);
    }

    
    const timeMap = {
        'today': 'today',
        'last hour': 'last1h',
        'last 24 hours': 'last24h',
        'this morning': 'today',
        'yesterday': 'yesterday',
        'last week': 'last7d',
        'past hour': 'last1h',
        'past 24 hours': 'last24h',
        'last 7 days': 'last7d'
    };
    let timePart = null;
    for (const [phrase, value] of Object.entries(timeMap)) {
        if (lower.includes(phrase)) {
            timePart = value;
            interpretation.push(`⏱️ Time: ${phrase} (${value})`);
            break;
        }
    }
    if (timePart) addCondition('time', timePart, null); 

    
    const severityMap = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low'
    };
    for (let sev in severityMap) {
        if (lower.includes(sev)) {
            addCondition('severity', severityMap[sev], `⚠️ Severity: ${sev.toUpperCase()}`);
        }
    }

    
    if (lower.includes('high confidence')) {
        addCondition('confidence', '>80', '📊 Confidence above 80%');
    } else if (lower.includes('medium confidence')) {
        addCondition('confidence', '>50', '📊 Confidence above 50%');
    } else if (lower.includes('low confidence')) {
        addCondition('confidence', '<50', '📊 Confidence below 50%');
    } else if (lower.includes('confidence')) {
        addCondition('confidence', '>50', '📊 Confidence above 50%');
    }

    
    const eventMap = {
        'c2': 'C2',
        'beaconing': 'Beaconing',
        'beacon': 'Beaconing',
        'brute force': 'Brute Force',
        'bruteforce': 'Brute Force',
        'port scan': 'Port Scan',
        'portscan': 'Port Scan',
        'exfiltration': 'Exfiltration',
        'exfil': 'Exfiltration',
        'ioc match': 'IOC Match',
        'ioc': 'IOC Match',
        'tor': 'Tor',
        'dns tunneling': 'DNS Tunneling',
        'dnstunnel': 'DNS Tunneling',
        'dns': 'DNS Tunneling',
        'scan': 'Port Scan',
        'scanning': 'Port Scan'
    };
    for (let key in eventMap) {
        if (lower.includes(key)) {
            addCondition('event', `"${eventMap[key]}"`, `🔍 Event: ${eventMap[key]}`);
        }
    }

    
    const countryMap = {
        'russia': 'RU',
        'china': 'CN',
        'north korea': 'KP',
        'iran': 'IR',
        'syria': 'SY',
        'cuba': 'CU',
        'venezuela': 'VE',
        'usa': 'US',
        'united states': 'US',
        'uk': 'GB',
        'germany': 'DE',
        'france': 'FR',
        'ukraine': 'UA'
    };
    for (let name in countryMap) {
        if (lower.includes(name)) {
            addCondition('country', countryMap[name], `🌍 Country: ${name}`);
        }
    }

    
    const ipRegex = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
    const ips = input.match(ipRegex);
    if (ips) {
        ips.forEach(ip => {
            addCondition('ip', ip, `📡 IP: ${ip}`);
        });
    }

    
    
    const hostRegex = /host\s+(\S+)/gi;
    let hostMatch;
    while ((hostMatch = hostRegex.exec(input)) !== null) {
        addCondition('host', hostMatch[1], `🖥️ Host: ${hostMatch[1]}`);
    }
    
    const words = input.split(/\s+/);
    for (let word of words) {
        const asset = assets.find(a => a.hostname.toLowerCase() === word.toLowerCase());
        if (asset) {
            addCondition('host', asset.hostname, `🖥️ Asset: ${asset.hostname}`);
        }
    }

    
    const iocPhrases = ['malicious ip', 'malicious ips', 'bad ip', 'bad ips', 'known malicious domains', 'threat intel', 'indicators', 'ioc'];
    for (let phrase of iocPhrases) {
        if (lower.includes(phrase)) {
            addCondition('ioc', 'true', `🚫 Indicator of Compromise`);
            break;
        }
    }

    
    const mitreMap = {
        'credential dumping': 'T1003',
        'persistence': 'Persistence',
        'lateral movement': 'Lateral Movement',
        'execution': 'Execution',
        'privilege escalation': 'Privilege Escalation',
        'defense evasion': 'Defense Evasion'
    };
    for (let phrase in mitreMap) {
        if (lower.includes(phrase)) {
            const val = mitreMap[phrase];
            if (val.startsWith('T')) {
                addCondition('mitre', val, `🎯 MITRE: ${val}`);
            } else {
                addCondition('tactic', `"${val}"`, `📋 Tactic: ${val}`);
            }
        }
    }

    
    const uebaPhrases = ['anomalous hosts', 'suspicious behaviour', 'suspicious behavior', 'unusual traffic', 'high ueba'];
    for (let phrase of uebaPhrases) {
        if (lower.includes(phrase)) {
            addCondition('ueba', 'high', `🧠 UEBA: High anomaly score`);
            break;
        }
    }

    
    const riskRegex = /risk (?:over|above|>)\s*(\d+)/i;
    const riskMatch = lower.match(riskRegex);
    if (riskMatch) {
        addCondition('risk', `>${riskMatch[1]}`, `📈 Risk > ${riskMatch[1]}`);
    } else if (lower.includes('highest risk')) {
        addCondition('risk', '>80', `📈 Risk > 80 (Highest)`);
    } else if (lower.includes('critical ai risk')) {
        addCondition('risk', '>95', `📈 Risk > 95 (Critical)`);
    } else if (lower.includes('risk')) {
        
        addCondition('risk', '>50', `📈 Risk above 50`);
    }

    
    let incidentTerms = [];
    if (lower.includes('incident')) {
        
        const hostMatchInc = lower.match(/involving\s+(\S+)/);
        if (hostMatchInc) {
            incidentTerms.push(`host:${hostMatchInc[1]}`);
            interpretation.push(`📁 Incident involving ${hostMatchInc[1]}`);
        }
        if (lower.includes('ioc')) {
            incidentTerms.push('ioc:true');
            interpretation.push(`📁 Incident with IOC matches`);
        }
        if (lower.includes('critical')) {
            incidentTerms.push('severity:critical');
            interpretation.push(`📁 Critical incidents`);
        }
        if (lower.includes('resolved')) {
            incidentTerms.push('status:resolved');
            interpretation.push(`📁 Resolved incidents`);
        }
        
        if (incidentTerms.length > 0) {
            addCondition('incident', incidentTerms.join(' AND '), `📁 Incidents: ${incidentTerms.join(' AND ')}`);
        } else {
            addCondition('incident', 'true', '📁 Any incident');
        }
    }

    
    if (lower.includes('case') || lower.includes('cases')) {
        let caseTerms = [];
        if (lower.includes('open')) {
            caseTerms.push('status:open');
            interpretation.push(`📂 Open cases`);
        }
        if (lower.includes('assigned to me')) {
            
            caseTerms.push('assignedTo:me');
            interpretation.push(`📂 Cases assigned to me`);
        }
        if (lower.includes('resolved')) {
            caseTerms.push('status:resolved');
            interpretation.push(`📂 Resolved cases`);
        }
        if (lower.includes('high priority')) {
            caseTerms.push('priority:P1 OR priority:P2');
            interpretation.push(`📂 High priority cases`);
        }
        if (caseTerms.length > 0) {
            addCondition('case', caseTerms.join(' AND '), `📂 Cases: ${caseTerms.join(' AND ')}`);
        } else {
            addCondition('case', 'true', '📂 Any case');
        }
    }

    
    const numRegex = /(more than|greater than|>)\s*(\d+)/i;
    let numMatch = lower.match(numRegex);
    if (numMatch) {
        
        let field = 'risk';
        if (lower.includes('countries')) field = 'country_count';
        else if (lower.includes('alerts')) field = 'alert_count';
        else if (lower.includes('packets')) field = 'packet_count';
        
        addCondition('risk', `>${numMatch[2]}`, `📈 Number comparison: > ${numMatch[2]}`);
    }

    
    let finalQuery = parts.join(' AND ');
    
    if (timePart) {
        finalQuery = `time:${timePart} AND ${finalQuery}`;
    }

    
    const uniqueParts = [...new Set(finalQuery.split(' AND '))];
    finalQuery = uniqueParts.join(' AND ');

    return { query: finalQuery, interpretation };
}

function matchesHuntingConditions(item, conditions) {
    
    
    
    for (const [key, values] of Object.entries(conditions)) {
        let match = false;
        switch (key) {
            case 'src':
                if (item.src) match = values.some(v => item.src.includes(v));
                break;
            case 'dst':
                if (item.dst) match = values.some(v => item.dst.includes(v));
                break;
            case 'protocol':
                if (item.proto) match = values.some(v => item.proto.toLowerCase().includes(v));
                break;
            case 'country':
                
                if (item.src || item.dst) {
                    const srcGeo = geoCache.get(item.src);
                    const dstGeo = geoCache.get(item.dst);
                    match = values.some(v => (srcGeo && srcGeo.code === v) || (dstGeo && dstGeo.code === v));
                }
                break;
            case 'severity':
                if (item.severity) match = values.some(v => item.severity === v);
                break;
            case 'risk':
                
                const riskVal = parseFloat(values[0]);
                if (!isNaN(riskVal)) {
                    const score = item.risk || item.score || 0;
                    if (values[0].startsWith('>')) match = score > riskVal;
                    else if (values[0].startsWith('<')) match = score < riskVal;
                    else match = score === riskVal;
                }
                break;
            case 'confidence':
                const confVal = parseFloat(values[0]);
                if (!isNaN(confVal) && item.confidence !== undefined) {
                    if (values[0].startsWith('>')) match = item.confidence > confVal;
                    else if (values[0].startsWith('<')) match = item.confidence < confVal;
                    else match = item.confidence === confVal;
                }
                break;
            case 'ioc':
                if (key === 'ioc' && values[0] === 'true') {
                    
                    match = iocs.some(i => i.value === item.src || i.value === item.dst);
                }
                break;
            case 'type':
                if (item.type) match = values.some(v => item.type === v);
                break;
            case 'host':
                if (item.host || item.src) match = values.some(v => (item.host || item.src).includes(v));
                break;
            case 'event':
                if (item.eventType) match = values.some(v => item.eventType.includes(v));
                break;
            default:
                match = true;
        }
        if (!match) return false;
    }
    return true;

}function runHuntingQuery(query) {
    const groups = parseHuntingQuery(query);
    if (groups.length === 0) {
        showToast('No valid filters found. Use key:value pairs.', 'warning');
        return;
    }

    
    const packetResults = globalPacketData.filter(p => matchesHuntingConditions(p, groups));
    const alertResults = timelineEvents.filter(a => matchesHuntingConditions(a, groups));
    const hostResults = [];
    for (const [host, entry] of hostStages.entries()) {
        const risk = mlInfoMap.get(host)?.score || 0;
        const status = mlInfoMap.get(host)?.status || 'OK';
        const stages = Array.from(entry.stages.keys());
        const hostItem = { host, risk, status, stages, src: host };
        if (matchesHuntingConditions(hostItem, groups)) {
            hostResults.push({ host, risk, status, stages });
        }
    }
    const iocResults = iocs.filter(ioc => matchesHuntingConditions(ioc, groups));

    
    let incidentResults = [];
    
    const incidentCondition = groups.some(group => group.some(cond => cond.key === 'incident'));
    if (incidentCondition) {
        incidentResults = incidents.filter(inc => {
            
            for (const group of groups) {
                let groupMatches = true;
                for (const cond of group) {
                    if (cond.key === 'incident') {
                        
                        const subQuery = cond.value;
                        
                        
                        if (subQuery.includes('host:')) {
                            const hostMatch = subQuery.match(/host:(\S+)/);
                            if (hostMatch) {
                                const hostVal = hostMatch[1];
                                if (![...inc.hosts].some(h => h.includes(hostVal))) {
                                    groupMatches = false;
                                    break;
                                }
                            }
                        }
                        if (subQuery.includes('severity:critical')) {
                            if (inc.severity !== 'critical') {
                                groupMatches = false;
                                break;
                            }
                        }
                        if (subQuery.includes('status:resolved')) {
                            if (inc.status !== 'resolved') {
                                groupMatches = false;
                                break;
                            }
                        }
                        if (subQuery.includes('ioc:true')) {
                            
                            const hasIOC = [...inc.alertIds].some(id => {
                                const alert = timelineEvents.find(e => e.id === id);
                                return alert && alert.evidence?.iocType;
                            });
                            if (!hasIOC) {
                                groupMatches = false;
                                break;
                            }
                        }
                    }
                }
                if (groupMatches) return true;
            }
            return false;
        });
    }

    
    let caseResults = [];
    const caseCondition = groups.some(group => group.some(cond => cond.key === 'case'));
    if (caseCondition) {
        caseResults = cases.filter(c => {
            for (const group of groups) {
                let groupMatches = true;
                for (const cond of group) {
                    if (cond.key === 'case') {
                        const subQuery = cond.value;
                        if (subQuery.includes('status:open')) {
                            if (c.status !== 'open') {
                                groupMatches = false;
                                break;
                            }
                        }
                        if (subQuery.includes('status:resolved')) {
                            if (c.status !== 'resolved') {
                                groupMatches = false;
                                break;
                            }
                        }
                        if (subQuery.includes('assignedTo:me')) {
                            
                            if (!c.assignedTo) {
                                groupMatches = false;
                                break;
                            }
                        }
                        if (subQuery.includes('priority:P1') || subQuery.includes('priority:P2')) {
                            if (c.priority !== 'P1' && c.priority !== 'P2') {
                                groupMatches = false;
                                break;
                            }
                        }
                    }
                }
                if (groupMatches) return true;
            }
            return false;
        });
    }

    
    huntingResults.packets = packetResults;
    huntingResults.alerts = alertResults;
    huntingResults.hosts = hostResults;
    huntingResults.iocs = iocResults;
    huntingResults.incidents = incidentResults;
    huntingResults.cases = caseResults;

    
    document.getElementById('hunting-packet-count').textContent = packetResults.length;
    document.getElementById('hunting-alert-count').textContent = alertResults.length;
    document.getElementById('hunting-host-count').textContent = hostResults.length;
    document.getElementById('hunting-ioc-count').textContent = iocResults.length;

    const incidentCountEl = document.getElementById('hunting-incident-count');
    if (incidentCountEl) incidentCountEl.textContent = incidentResults.length;
    const caseCountEl = document.getElementById('hunting-case-count');
    if (caseCountEl) caseCountEl.textContent = caseResults.length;

    
    renderHuntingResults();
}

function renderHuntingIncidents() {
    const tbody = document.getElementById('hunting-incident-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const incidents = huntingResults.incidents || [];
    if (incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No incidents match.</td></tr>';
        return;
    }
    incidents.forEach(inc => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>#${inc.id}</td>
            <td>${inc.title}</td>
            <td><span class="severity-${inc.severity}">${inc.severity.toUpperCase()}</span></td>
            <td><span class="status-badge status-${inc.status}">${inc.status.toUpperCase()}</span></td>
            <td>${[...inc.hosts].join(', ')}</td>
            <td>${inc.alertIds.size}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderHuntingCases() {
    const tbody = document.getElementById('hunting-case-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const cases = huntingResults.cases || [];
    if (cases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No cases match.</td></tr>';
        return;
    }
    cases.forEach(c => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>#${c.id}</td>
            <td>${c.title}</td>
            <td><span class="severity-${c.severity}">${c.severity.toUpperCase()}</span></td>
            <td><span class="status-badge status-${c.status}">${c.status.toUpperCase()}</span></td>
            <td>${c.assignedTo || '—'}</td>
            <td>${c.alerts ? c.alerts.length : 0}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderHuntingResults() {
    renderHuntingPackets();
    renderHuntingAlerts();
    renderHuntingHosts();
    renderHuntingIOCs();
    renderHuntingIncidents();
    renderHuntingCases();
}
function renderHuntingPackets() {
    const tbody = document.getElementById('hunting-packet-tbody');
    if (!tbody) {console.error('Hunting packet tbody not found!'); return;}
    tbody.innerHTML = '';
    const packets = huntingResults.packets.slice(0, 200);
    if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-muted">No packets match.</td></tr>';
        return;
    }
    packets.forEach(p => {
        const row = document.createElement('tr');
        const payload = p.payload ? sanitize(p.payload) : '';
        const short = payload.length > 30 ? payload.slice(0, 30)+'…' : payload;
        const pivotCell = document.createElement('td');
        const pivot = createPivotDropdown(p, 'packet');
        pivotCell.appendChild(pivot);
        row.innerHTML = `
            <td>${p.time || '—'}</td>
            <td><span class="ip-intel-trigger" data-ip="${p.src}">${p.src}</span></td>
            <td><span class="ip-intel-trigger" data-ip="${p.dst}">${p.dst}</span></td>
            <td>${p.proto || '—'}</td>
            <td>${p.dst_port || 'any'}</td>
            <td title="${payload}">${short || '—'}</td>
        `;
        row.appendChild(pivotCell);
        tbody.appendChild(row);
    });
}



function createPivotDropdown(item, type) {
    const container = document.createElement('div');
    container.className = 'pivot-dropdown';
    const btn = document.createElement('button');
    btn.className = 'pivot-btn';
    btn.innerHTML = '<i class="fas fa-ellipsis-v"></i>';
    const content = document.createElement('div');
    content.className = 'pivot-dropdown-content';
    
    const actions = [];
    if (type === 'packet' || type === 'alert' || type === 'host') {
        const ip = item.src || item.dst || item.host;
        if (ip) {
            actions.push({ label: 'Hunt Similar', action: () => huntSimilar(ip) });
            actions.push({ label: 'View Timeline', action: () => viewTimelineForNode(ip) });
            actions.push({ label: 'Open Investigation Graph', action: () => openGraphForIP(ip) });
            actions.push({ label: 'View Cases', action: () => viewCasesForIP(ip) });
            actions.push({ label: 'View IOC Hits', action: () => viewIOCForIP(ip) });
        }
    }
    if (type === 'ioc') {
        actions.push({ label: 'Hunt This IOC', action: () => huntIOC(item.value) });
    }
    actions.forEach(a => {
        const btn2 = document.createElement('button');
        btn2.textContent = a.label;
        btn2.addEventListener('click', function(e) {
            e.stopPropagation();
            a.action();
            content.classList.remove('show');
        });
        content.appendChild(btn2);
    });
    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        content.classList.toggle('show');
    });
    container.appendChild(btn);
    container.appendChild(content);
    
    document.addEventListener('click', function() {
        content.classList.remove('show');
    });
    return container;
}

function huntSimilar(ip) {
    document.getElementById('hunting-query-input').value = `src:${ip} OR dst:${ip}`;
    document.getElementById('hunting-run-btn').click();
}

function openGraphForIP(ip) {
    switchView('investigation');
    
}

function viewCasesForIP(ip) {
    
    switchView('cases');
    
    const searchInput = document.getElementById('case-search') || document.getElementById('alert-search');
    if (searchInput) {
        searchInput.value = ip;
        renderCasesTable();
    }
}

function viewIOCForIP(ip) {
    switchView('ioc');
    
    const iocSearch = document.getElementById('ioc-search');
    if (iocSearch) {
        iocSearch.value = ip;
        renderIOCs();
    }
}

function huntIOC(value) {
    document.getElementById('hunting-query-input').value = `ioc:true host:${value}`;
    document.getElementById('hunting-run-btn').click();
}

function renderHuntingAlerts() {
    const tbody = document.getElementById('hunting-alert-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const alerts = huntingResults.alerts.slice(0, 200);
    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-muted">No alerts match.</td></tr>';
        return;
    }
    alerts.forEach(a => {
        const row = document.createElement('tr');
        const confidenceBar = a.confidence !== undefined ? `
            <div class="confidence-bar" style="width:60px; height:12px; display:inline-block;">
                <div class="confidence-fill" style="width:${a.confidence}%; background:${confidenceColor(a.confidence)};"></div>
            </div>
        ` : '—';
        row.innerHTML = `
            <td>${formatAlertTime(a) || '—'}</td>
            <td><span class="severity-${a.severity}">${a.severity.toUpperCase()}</span></td>
            <td>${a.eventType}</td>
            <td>${a.details}${a.src ? ` (${a.src} → ${a.dst})` : ''}</td>
            <td>${confidenceBar}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderHuntingHosts() {
    const tbody = document.getElementById('hunting-host-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const hosts = huntingResults.hosts.slice(0, 200);
    if (hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No hosts match.</td></tr>';
        return;
    }
    hosts.forEach(h => {
        const row = document.createElement('tr');
        const riskColor = h.risk > 80 ? '#ef4444' : h.risk > 50 ? '#f59e0b' : '#10b981';
        const stagesStr = h.stages.join(', ') || '—';
        row.innerHTML = `
            <td><span class="ip-intel-trigger" data-ip="${h.host}">${h.host}</span></td>
            <td style="color:${riskColor}; font-weight:600;">${h.risk.toFixed(1)}</td>
            <td>${h.status}</td>
            <td>${stagesStr}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderHuntingIOCs() {
    const tbody = document.getElementById('hunting-ioc-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const iocs = huntingResults.iocs.slice(0, 200);
    if (iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No IOCs match.</td></tr>';
        return;
    }
    iocs.forEach(i => {
        const row = document.createElement('tr');
        const severityClass = i.severity || 'medium';
        row.innerHTML = `
            <td><span class="ioc-type-badge">${i.type.toUpperCase()}</span></td>
            <td><code>${i.value}</code></td>
            <td><span class="severity-${severityClass}">${severityClass.toUpperCase()}</span></td>
            <td>${i.matchCount || 0}</td>
        `;
        tbody.appendChild(row);
    });
}

document.querySelectorAll('.hunting-tab').forEach(tab => {
    tab.addEventListener('click', function() {
        document.querySelectorAll('.hunting-tab').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        const tabName = this.dataset.tab;
        document.querySelectorAll('.hunting-result-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById(`hunting-results-${tabName}`).classList.remove('hidden');
    });
});

document.querySelectorAll('.hunt-template').forEach(btn => {
    btn.addEventListener('click', function() {
        const query = this.dataset.query;
        if (query) {
            document.getElementById('hunting-query-input').value = query;
            document.getElementById('hunting-run-btn').click();
        }
    });
});

document.getElementById('hunting-run-btn').addEventListener('click', function() {
    let query = document.getElementById('hunting-query-input').value.trim();
    if (!query) {
        showToast('Please enter a query.', 'warning');
        return;
    }

    const isStructured = /[a-zA-Z_]+:/.test(query);
    const isNatural = !isStructured || query.split(/\s+/).some(word => ['show', 'find', 'hosts', 'alerts', 'from', 'to', 'in', 'with', 'having', 'where'].includes(word.toLowerCase()));

    let translatedQuery = query;
    let interpretation = [];
    if (isNatural || !isStructured) {
        const parsed = parseNaturalLanguageQuery(query);
        if (parsed.query) {
            translatedQuery = parsed.query;
            interpretation = parsed.interpretation;
            
            const div = document.getElementById('hunting-translation');
            if (div) {
                let html = '<div style="background:var(--surface-light); padding:12px; border-radius:8px; margin:8px 0;">';
                html += '<strong><i class="fas fa-brain"></i> AI Interpretation</strong><br>';
                if (interpretation.length) {
                    html += '<ul style="list-style:none; padding:0; margin:4px 0;">';
                    interpretation.forEach(item => {
                        html += `<li style="padding:2px 0;">✓ ${item}</li>`;
                    });
                    html += '</ul>';
                }
                
                html += `<div style="font-size:13px; color:var(--text-muted);">🔍 Searching for: <code>${translatedQuery}</code></div>`;
                html += '</div>';
                div.innerHTML = html;
            }
            showToast(`🔍 Translated to: ${translatedQuery}`, 'info');
        } else {
            
            translatedQuery = query;
            document.getElementById('hunting-translation').innerHTML = '';
        }
    } else {
        document.getElementById('hunting-translation').innerHTML = '';
    }

    runHuntingQuery(translatedQuery);

    
    
    setTimeout(() => {
        const total = huntingResults.packets.length + huntingResults.alerts.length + huntingResults.hosts.length + huntingResults.iocs.length + (huntingResults.incidents?.length || 0) + (huntingResults.cases?.length || 0);
        const div = document.getElementById('hunting-translation');
        if (div) {
            
            const existing = div.innerHTML;
            div.innerHTML = existing + `<div style="font-size:13px; color:var(--text-muted); margin-top:4px;">📊 Estimated results: ${total} items</div>`;
        }
    }, 100);
});


document.getElementById('hunting-query-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        document.getElementById('hunting-run-btn').click();
    }
});

document.getElementById('hunting-clear').addEventListener('click', function() {
    document.getElementById('hunting-query-input').value = '';
    huntingResults = { packets: [], alerts: [], hosts: [], iocs: [] };
    document.getElementById('hunting-packet-count').textContent = '0';
    document.getElementById('hunting-alert-count').textContent = '0';
    document.getElementById('hunting-host-count').textContent = '0';
    document.getElementById('hunting-ioc-count').textContent = '0';
    renderHuntingResults();
});

document.getElementById('hunting-export').addEventListener('click', function() {
    const data = {
        query: document.getElementById('hunting-query-input').value,
        timestamp: new Date().toISOString(),
        results: huntingResults
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hunt_results_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Results exported.', 'success');
});

document.getElementById('hunting-save-btn').addEventListener('click', function() {
    const query = document.getElementById('hunting-query-input').value.trim();
    if (!query) {
        showToast('Enter a query first.', 'warning');
        return;
    }
    try {
        let saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
        saved.push({ query, timestamp: Date.now() });
        localStorage.setItem('huntingSavedQueries', JSON.stringify(saved));
        showToast('Query saved.', 'success');
    } catch (e) {
        showToast('Could not save query.', 'danger');
    }
});

function parseHuntingQuery(query) {
    
    if (!query.includes(' ')) {
        const parts = query.split(':');
        if (parts.length === 2) {
            return [[{ key: parts[0], value: parts[1], negated: false }]];
        }
        return [];
    }

    
    let normalized = query.replace(/\bNOT\s+/gi, '!');
    
    const groups = normalized.split(/\s+OR\s+/i).map(g => g.trim()).filter(g => g);
    const resultGroups = [];
    for (const group of groups) {
        const tokens = group.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
        const conditions = [];
        for (let token of tokens) {
            let negated = false;
            if (token.startsWith('!')) {
                negated = true;
                token = token.slice(1);
            }
            const parts = token.split(':');
            if (parts.length >= 2) {
                const key = parts[0];
                let value = parts.slice(1).join(':');
                if (value.startsWith('"') && value.endsWith('"')) {
                    value = value.slice(1, -1);
                }
                conditions.push({ key, value, negated });
            }
        }
        if (conditions.length) {
            resultGroups.push(conditions);
        }
    }
    return resultGroups;
}

function evaluateNumeric(actual, value) {
    if (typeof actual !== 'number') return false;
    if (value.startsWith('>')) return actual > parseFloat(value.slice(1));
    if (value.startsWith('<')) return actual < parseFloat(value.slice(1));
    if (value.startsWith('>=')) return actual >= parseFloat(value.slice(2));
    if (value.startsWith('<=')) return actual <= parseFloat(value.slice(2));
    return actual === parseFloat(value);
}

function matchesHuntingConditions(item, groups) {
    
    if (!groups || groups.length === 0) return true;
    
    for (const group of groups) {
        let groupMatches = true;
        for (const cond of group) {
            const match = evaluateCondition(item, cond);
            if (cond.negated) {
                if (match) { groupMatches = false; break; }
            } else {
                if (!match) { groupMatches = false; break; }
            }
        }
        if (groupMatches) return true; 
    }
    return false;
}

function evaluateCondition(item, cond) {
    const { key, value } = cond;
    let actual = null;
    
    switch (key) {
        case 'src':
            actual = item.src || item.host || null;
            break;
        case 'dst':
            actual = item.dst || null;
            break;
        case 'protocol':
            actual = item.proto || null;
            break;
        case 'severity':
            actual = item.severity || null;
            break;
        case 'confidence':
            actual = item.confidence !== undefined ? item.confidence : null;
            break;
        case 'country':
            if (item.src) {
                const geo = geoCache.get(item.src);
                if (geo) actual = geo.code;
            } else if (item.dst) {
                const geo = geoCache.get(item.dst);
                if (geo) actual = geo.code;
            }
            break;
        case 'risk':
            actual = item.risk || item.score || 0;
            break;
        case 'type':
            actual = item.type || null;
            break;
        case 'host':
            actual = item.host || item.src || null;
            break;
        case 'event':
            actual = item.eventType || null;
            break;
        case 'ioc':
            
            if (item.src || item.dst) {
                actual = iocs.some(i => i.value === item.src || i.value === item.dst);
                
                return (value === 'true') === actual;
            }
            return false;

        case 'payload':
            actual = item.payload || null;
            break;
        case 'src_port':
            actual = item.src_port !== undefined ? item.src_port : null;
            break;
        case 'dst_port':
            actual = item.dst_port !== undefined ? item.dst_port : null;
            break;

        case 'ip':
            if (item.src || item.dst) {
                actual = (item.src === value || item.dst === value);
                return actual;
            }
            return false;
            
        case 'ueba':
            if (item.uebaScore !== undefined) {
                actual = item.uebaScore;
                
                if (value === 'high') return actual > 70;
                else if (value === 'medium') return actual > 40 && actual <= 70;
                else if (value === 'low') return actual <= 40;
                else return actual === parseFloat(value);
            }
            return false;

        case 'risk':
            
            actual = item.risk || item.score || 0;
            return evaluateNumeric(actual, value);

        case 'mitre':
            if (item.mitre) {
                actual = item.mitre;
                return actual === value;
            }
            return false;

        case 'tactic':
            if (item.mitre) {
                const tactic = MITRE_TECHNIQUES[item.mitre]?.tactic || '';
                return tactic === value;
            }
            return false;

        case 'incident':
            
            
            
            return true;

        case 'case':
            
            return true;

        case 'time':
            
            return true;

        default:
            return false;
        }
    if (actual === null) return false;

    if (typeof actual === 'number' && !isNaN(parseFloat(value))) {
        
        const numVal = parseFloat(value);
        if (value.startsWith('>')) return actual > numVal;
        if (value.startsWith('<')) return actual < numVal;
        if (value.startsWith('>=')) return actual >= numVal;
        if (value.startsWith('<=')) return actual <= numVal;
        return actual === numVal;
    } else {
        
        return String(actual).toLowerCase().includes(value.toLowerCase());
    }
}

function loadSavedQueries() {
    try {
        const saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
        const library = document.getElementById('saved-query-library');
        if (!library) return;
        if (saved.length === 0) {
            library.innerHTML = '<span class="text-muted" style="padding: 4px;">No saved queries.</span>';
            return;
        }
        let html = '';
        saved.forEach((q, index) => {
            const display = q.query.length > 30 ? q.query.slice(0, 30)+'…' : q.query;
            html += `
                <div class="saved-query-item" data-index="${index}">
                    <span class="query-text" title="${q.query}">${display}</span>
                    <button class="run-query-btn" title="Run query"><i class="fas fa-play"></i></button>
                    <button class="edit-query-btn" title="Edit query"><i class="fas fa-edit"></i></button>
                    <button class="delete-query-btn" title="Delete query"><i class="fas fa-trash"></i></button>
                </div>
            `;
        });
        library.innerHTML = html;
        
        library.querySelectorAll('.run-query-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const idx = parseInt(this.closest('.saved-query-item').dataset.index);
                const saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
                if (saved[idx]) {
                    document.getElementById('hunting-query-input').value = saved[idx].query;
                    document.getElementById('hunting-run-btn').click();
                }
            });
        });
        library.querySelectorAll('.edit-query-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const idx = parseInt(this.closest('.saved-query-item').dataset.index);
                const saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
                if (saved[idx]) {
                    document.getElementById('hunting-query-input').value = saved[idx].query;
                    document.getElementById('hunting-query-input').focus();
                }
            });
        });
        library.querySelectorAll('.delete-query-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const idx = parseInt(this.closest('.saved-query-item').dataset.index);
                showConfirmModal('Delete Saved Query', 'Delete this saved query?', () => {
                    let saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
                    saved.splice(idx, 1);
                    localStorage.setItem('huntingSavedQueries', JSON.stringify(saved));
                    loadSavedQueries();
                    showToast('Query deleted.', 'success');
                });
            });
        });
    } catch (e) {
        console.warn('Error loading saved queries:', e);
    }
  }


document.getElementById('hunting-save-btn').addEventListener('click', function() {
    const query = document.getElementById('hunting-query-input').value.trim();
    if (!query) {
        showToast('Enter a query first.', 'warning');
        return;
    }
    try {
        let saved = JSON.parse(localStorage.getItem('huntingSavedQueries') || '[]');
        
        if (!saved.some(q => q.query === query)) {
            saved.push({ query, timestamp: Date.now() });
            localStorage.setItem('huntingSavedQueries', JSON.stringify(saved));
            loadSavedQueries();
            showToast('Query saved.', 'success');
        } else {
            showToast('Query already saved.', 'info');
        }
    } catch (e) {
        showToast('Could not save query.', 'danger');
    }
});




document.getElementById('saved-query-toggle').addEventListener('click', function() {
    const library = document.getElementById('saved-query-library');
    if (library) {
        library.style.display = library.style.display === 'none' ? 'flex' : 'none';
        this.textContent = library.style.display === 'none' ? 'Show' : 'Hide';
    }
});




const techData = {};
const tacticData = {};

function renderMitreCoverage() {
    

    
    Object.keys(MITRE_TECHNIQUES).forEach(tech => {
        techData[tech] = {
            count: 0,
            hosts: new Set(),
            severities: { critical: 0, high: 0, medium: 0, low: 0 },
            confidenceSum: 0,
            confidenceCount: 0,
            sources: new Set(),
            events: [],
            timeline: {}
        };
    });

    
    timelineEvents.forEach(ev => {
        if (!ev.mitre) return;
        const tech = ev.mitre;
        if (!techData[tech]) return; 
        const data = techData[tech];
        data.count++;
        if (ev.src) data.hosts.add(ev.src);
        if (ev.severity && data.severities[ev.severity] !== undefined) {
            data.severities[ev.severity]++;
        }
        if (ev.confidence !== undefined) {
            data.confidenceSum += ev.confidence;
            data.confidenceCount++;
        }
        if (ev.source) data.sources.add(ev.source);
        data.events.push(ev.id); 
        
        const date = new Date(ev.eventTimestamp || Date.now()).toISOString().slice(0,10);
        data.timeline[date] = (data.timeline[date] || 0) + 1;
    });

    
    TACTIC_ORDER.forEach(tactic => {
        const techs = TACTIC_TECHNIQUES[tactic] || [];
        let totalDetections = 0;
        let uniqueHosts = new Set();
        let severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        let confidenceSum = 0, confidenceCount = 0;
        let sources = new Set();
        let covered = 0;
        techs.forEach(tech => {
            const d = techData[tech];
            if (d.count > 0) covered++;
            totalDetections += d.count;
            d.hosts.forEach(h => uniqueHosts.add(h));
            Object.keys(severityCounts).forEach(sev => {
                severityCounts[sev] += d.severities[sev];
            });
            confidenceSum += d.confidenceSum;
            confidenceCount += d.confidenceCount;
            d.sources.forEach(s => sources.add(s));
        });
        tacticData[tactic] = {
            total: techs.length,
            covered: covered,
            detections: totalDetections,
            hosts: uniqueHosts.size,
            severity: severityCounts,
            avgConfidence: confidenceCount ? (confidenceSum / confidenceCount) : 0,
            sources: Array.from(sources)
        };
    });

    
    const container = document.getElementById('tactic-coverage-container');
    if (!container) return;
    container.innerHTML = '';
    TACTIC_ORDER.forEach(tactic => {
        const stats = tacticData[tactic];
        if (!stats) return;
        const pct = stats.total ? Math.round((stats.covered / stats.total) * 100) : 0;
        const div = document.createElement('div');
        div.style.cssText = 'display:flex; align-items:center; gap:12px; padding:4px 0;';
        div.innerHTML = `
            <span style="width:160px; font-weight:500;">${tactic}</span>
            <div style="flex:1; height:24px; background:var(--surface-light); border-radius:12px; overflow:hidden; position:relative;">
                <div style="width:${pct}%; height:100%; background:${pct >= 80 ? 'var(--secondary)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)'}; transition:width 0.6s;"></div>
                <span style="position:absolute; left:50%; top:50%; transform:translate(-50%, -50%); font-size:12px; font-weight:600; color:var(--text);">${pct}%</span>
            </div>
            <span style="min-width:80px; text-align:right; font-size:13px; color:var(--text-muted);">${stats.covered}/${stats.total} techs</span>
            <span style="font-size:13px; color:var(--text-muted);">🧑‍💻 ${stats.hosts} hosts</span>
            <span style="font-size:13px; color:var(--text-muted);">📊 ${stats.detections} detections</span>
        `;
        container.appendChild(div);
    });

    
    const tbody = document.getElementById('mitre-technique-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const sortedTechs = Object.keys(techData).sort((a,b) => techData[b].count - techData[a].count);
    let totalDetections = 0;
    sortedTechs.forEach(tech => {
        const d = techData[tech];
        totalDetections += d.count;
        const info = MITRE_TECHNIQUES[tech] || { name: 'Unknown', tactic: 'Other' };
        const severityStr = Object.entries(d.severities)
            .filter(([k,v]) => v > 0)
            .map(([k,v]) => `<span class="severity-${k}">${k}: ${v}</span>`)
            .join(' ');
        const sourceStr = Array.from(d.sources).join(', ') || '—';
        const avgConf = d.confidenceCount ? (d.confidenceSum / d.confidenceCount).toFixed(1) : '—';
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        row.innerHTML = `
            <td><a href="${info.url}" target="_blank" class="mitre-badge">${tech}</a></td>
            <td>${info.name}</td>
            <td>${d.hosts.size}</td>
            <td><strong>${d.count}</strong></td>
            <td>${severityStr}</td>
            <td>${sourceStr}</td>
            <td>${avgConf}%</td>
        `;
        row.addEventListener('click', () => openTechniqueDetail(tech, techData[tech]));
        tbody.appendChild(row);
    });
    document.getElementById('technique-count').textContent = totalDetections;

    
    const uncoveredContainer = document.getElementById('uncovered-techniques-container');
    if (!uncoveredContainer) return;
    const uncovered = Object.keys(techData).filter(tech => techData[tech].count === 0);
    document.getElementById('uncovered-count').textContent = uncovered.length;
    if (uncovered.length === 0) {
        uncoveredContainer.innerHTML = '<span style="color:var(--secondary);">🎉 All techniques covered!</span>';
    } else {
        uncoveredContainer.innerHTML = uncovered.map(tech => {
            const info = MITRE_TECHNIQUES[tech] || { name: 'Unknown' };
            return `<span class="mitre-badge" style="background:var(--surface-light); color:var(--text-muted);">${tech} (${info.name})</span>`;
        }).join(' ');
    }
}


let currentTechniqueDetail = null;
let detailChartInstance = null;

function openTechniqueDetail(techId, data) {
    const modal = document.getElementById('technique-detail-modal');
    const title = document.getElementById('technique-detail-title');
    const content = document.getElementById('technique-detail-content');
    if (!modal || !title || !content) return;

    const info = MITRE_TECHNIQUES[techId] || { name: 'Unknown', tactic: 'Other' };
    title.textContent = `${techId} – ${info.name}`;

    
    const severityStr = Object.entries(data.severities)
        .filter(([k,v]) => v > 0)
        .map(([k,v]) => `${k}: ${v}`)
        .join(' | ');
    const avgConf = data.confidenceCount ? (data.confidenceSum / data.confidenceCount).toFixed(1) : '—';
    const sources = Array.from(data.sources).join(', ') || '—';
    const hostList = Array.from(data.hosts).join(', ') || 'None';
    const severity = ev.severity || 'low';

    let html = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;">
            <div><strong>Total Detections:</strong> ${data.count}</div>
            <div><strong>Unique Hosts:</strong> ${data.hosts.size}</div>
            <div><strong>Average Confidence:</strong> ${avgConf}%</div>
            <div><strong>Detection Sources:</strong> ${sources}</div>
            <div><strong>Severity:</strong> ${severityStr}</div>
            <div><strong>Tactic:</strong> ${info.tactic}</div>
        </div>
        <div><strong>Hosts:</strong> ${hostList}</div>
        <hr style="border-color:var(--border); margin:16px 0;">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div>
                <h4>Severity Distribution</h4>
                <canvas id="detail-severity-chart" height="120"></canvas>
            </div>
            <div>
                <h4>Timeline (last 30 days)</h4>
                <canvas id="detail-timeline-chart" height="120"></canvas>
            </div>
        </div>
        <hr style="border-color:var(--border); margin:16px 0;">
        <h4>Events</h4>
        <div style="max-height:200px; overflow-y:auto; border:1px solid var(--border); border-radius:8px;">
            <table style="width:100%; font-size:13px;">
                <thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Details</th><th>Source</th></tr></thead>
                <tbody>
    `;
    
    const events = timelineEvents.filter(e => e.mitre === techId);
    events.slice(0, 50).forEach(ev => {
        html += `
            <tr style="cursor:pointer;" onclick="showPacketDrilldown('${ev.id}')">
                <td>${formatAlertTime(ev)}</td>
                <span><strong>Severity:</strong> <span class="severity-${severity}">${severity.toUpperCase()}</span></span>
                <td>${ev.eventType}</td>
                <td>${ev.details}</td>
                <td>${ev.source || '—'}</td>
            </tr>
        `;
    });
    html += `</tbody></table></div>`;

    content.innerHTML = html;
    modal.classList.remove('hidden');

    
    setTimeout(() => {
        drawSeverityChart(data.severities);
        drawTimelineChart(data.timeline);
    }, 100);

    currentTechniqueDetail = techId;
}

function drawSeverityChart(severities) {
    const ctx = document.getElementById('detail-severity-chart')?.getContext('2d');
    if (!ctx) return;
    if (detailChartInstance) detailChartInstance.destroy();
    detailChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [severities.critical, severities.high, severities.medium, severities.low],
                backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#10b981']
            }]
        },
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom', labels: { color: '#ccc' } } } }
    });
}

function drawTimelineChart(timeline) {
    const ctx = document.getElementById('detail-timeline-chart')?.getContext('2d');
    if (!ctx) return;
    
    const dates = Object.keys(timeline).sort();
    const counts = dates.map(d => timeline[d]);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: 'Detections',
                data: counts,
                borderColor: '#6366f1',
                backgroundColor: 'rgba(99,102,241,0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true, ticks: { color: '#ccc' } }, x: { ticks: { color: '#ccc', maxTicksLimit: 10 } } }, plugins: { legend: { labels: { color: '#ccc' } } } }
    });
}


document.getElementById('close-technique-detail')?.addEventListener('click', () => {
    document.getElementById('technique-detail-modal').classList.add('hidden');
    if (detailChartInstance) {
        detailChartInstance.destroy();
        detailChartInstance = null;
    }
});


function exportNavigatorLayer() {
    const layer = {
        name: "NeoShield Coverage",
        versions: { attack: "14", navigator: "4.9" },
        domain: "enterprise-attack",
        description: "Detections from NeoShield",
        techniques: []
    };
    Object.keys(techData).forEach(tech => {
        const d = techData[tech];
        if (d.count > 0) {
            const score = Math.min(d.count, 100); 
            const color = score >= 80 ? '#ef4444' : score >= 50 ? '#f59e0b' : '#10b981';
            layer.techniques.push({
                techniqueID: tech,
                score: score,
                color: color,
                comment: `${d.count} detections, ${d.hosts.size} hosts`
            });
        }
    });
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `navigator_layer_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Navigator layer exported.', 'success');
}

document.getElementById('export-navigator')?.addEventListener('click', exportNavigatorLayer);

function loadAssets() {
    try {
        const stored = localStorage.getItem('neoShieldAssets');
        if (stored) {
            assets = JSON.parse(stored);
            assets = assets.map(a => ({
                ...a,
                criticality: a.criticality || 'Medium',
                os: a.os || 'Unknown',
                tags: a.tags || [],
                riskHistory: a.riskHistory || [{ timestamp: a.createdAt || Date.now(), score: a.risk || 0 }],
                status: a.status || (a.risk >= 80 ? 'Blocked' : a.risk >= 50 ? 'Under Investigation' : 'Healthy')
            }));
            nextAssetId = assets.reduce((max, a) => Math.max(max, a.id || 0), 0) + 1;
        } else {
            assets = [];
            nextAssetId = 1;
        }
    } catch (e) {
        assets = [];
        nextAssetId = 1;
    }
}

function saveAssets() {
    try {
        localStorage.setItem('neoShieldAssets', JSON.stringify(assets));
    } catch (e) {}
}

function createOrUpdateAsset(ip, data) {
    let asset = getAssetByIdentifier(ip);
    if (!asset) {
        asset = {
            id: nextAssetId++,
            ip: ip,
            hostname: data.hostname || ip,
            owner: data.owner || 'Unknown',
            risk: data.risk || 0,
            alerts: data.alerts || 0,
            status: data.status || 'Healthy',
            criticality: data.criticality || 'Medium',
            os: data.os || 'Unknown',
            tags: data.tags || [],
            riskHistory: [{ timestamp: Date.now(), score: data.risk || 0 }],
            createdAt: Date.now(),
            lastSeen: Date.now()
        };
        assets.push(asset);
    } else {
        if (data.hostname) asset.hostname = data.hostname;
        if (data.owner) asset.owner = data.owner;
        if (data.risk !== undefined && asset.risk !== data.risk) {
            asset.risk = data.risk;
            asset.riskHistory.push({ timestamp: Date.now(), score: data.risk });
            if (asset.riskHistory.length > 100) asset.riskHistory.shift();
        }
        if (data.alerts !== undefined) asset.alerts = data.alerts;
        if (data.status) asset.status = data.status;
        if (data.criticality) asset.criticality = data.criticality;
        if (data.os) asset.os = data.os;
        if (data.tags) asset.tags = data.tags;
        asset.lastSeen = Date.now();
    }
    saveAssets();
    renderAssetsTable();
    return asset;
}

function deleteAsset(id) {
    assets = assets.filter(a => a.id !== id);
    saveAssets();
    renderAssetsTable();
}
function openAssetModal(assetId = null) {
    const modal = document.getElementById('asset-modal');
    const title = document.getElementById('asset-modal-title');
    const form = document.getElementById('asset-form');
    form.reset();

    if (assetId) {
        const asset = assets.find(a => a.id === assetId);
        if (!asset) return;
        title.textContent = 'Edit Asset';
        document.getElementById('asset-ip').value = asset.ip;
        document.getElementById('asset-hostname').value = asset.hostname;
        document.getElementById('asset-owner').value = asset.owner;
        document.getElementById('asset-risk').value = asset.risk;
        document.getElementById('asset-criticality').value = asset.criticality || 'Medium';
        document.getElementById('asset-os').value = asset.os || '';
        document.getElementById('asset-tags').value = (asset.tags || []).join(', ');
        document.getElementById('asset-status').value = asset.status;
        document.getElementById('asset-alerts').value = asset.alerts;
        form.dataset.assetId = assetId;
    } else {
        title.textContent = 'Add Asset';
        document.getElementById('asset-ip').value = '';
        document.getElementById('asset-hostname').value = '';
        document.getElementById('asset-owner').value = '';
        document.getElementById('asset-risk').value = '0';
        document.getElementById('asset-criticality').value = 'Medium';
        document.getElementById('asset-os').value = '';
        document.getElementById('asset-tags').value = '';
        document.getElementById('asset-status').value = 'Healthy';
        document.getElementById('asset-alerts').value = '0';
        form.dataset.assetId = '';
    }
    modal.classList.remove('hidden');
}

document.getElementById('add-asset-btn')?.addEventListener('click', () => openAssetModal());
document.getElementById('close-asset-modal')?.addEventListener('click', () => {
    document.getElementById('asset-modal').classList.add('hidden');
});
document.getElementById('cancel-asset-btn')?.addEventListener('click', () => {
    document.getElementById('asset-modal').classList.add('hidden');
});
document.getElementById('asset-form')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const assetId = this.dataset.assetId;
    const ip = document.getElementById('asset-ip').value.trim();
    if (!ip) {
        showToast('IP address is required.', 'warning');
        return;
    }
    const hostname = document.getElementById('asset-hostname').value.trim() || ip;
    const owner = document.getElementById('asset-owner').value.trim() || 'Unknown';
    const risk = parseFloat(document.getElementById('asset-risk').value) || 0;
    const criticality = document.getElementById('asset-criticality').value;
    const os = document.getElementById('asset-os').value.trim() || 'Unknown';
    const tags = document.getElementById('asset-tags').value.split(',').map(s => s.trim()).filter(Boolean);
    const status = document.getElementById('asset-status').value;
    const alerts = parseInt(document.getElementById('asset-alerts').value) || 0;

    if (assetId) {
        const idx = assets.findIndex(a => a.id === parseInt(assetId));
        if (idx !== -1) {
            const oldRisk = assets[idx].risk;
            assets[idx] = {
                ...assets[idx],
                ip,
                hostname,
                owner,
                risk,
                criticality,
                os,
                tags,
                status,
                alerts,
                lastSeen: Date.now()
            };
            if (oldRisk !== risk) {
                assets[idx].riskHistory.push({ timestamp: Date.now(), score: risk });
                if (assets[idx].riskHistory.length > 100) assets[idx].riskHistory.shift();
            }
        }
    } else {
        if (getAssetByIdentifier(ip)) {
            showToast('Asset with this IP already exists.', 'warning');
            return;
        }
        createOrUpdateAsset(ip, { hostname, owner, risk, criticality, os, tags, status, alerts });
    }
    saveAssets();
    renderAssetsTable();
    document.getElementById('asset-modal').classList.add('hidden');
    showToast(`Asset ${ip} saved.`, 'success');
});

document.getElementById('export-assets-btn')?.addEventListener('click', function() {
    if (assets.length === 0) {
        showToast('No assets to export.', 'warning');
        return;
    }
    const headers = ['IP', 'Hostname', 'Owner', 'Risk', 'Alerts', 'Status', 'Last Seen'];
    const rows = assets.map(a => [
        a.ip, a.hostname, a.owner, a.risk.toFixed(1), a.alerts, a.status,
        a.lastSeen ? new Date(a.lastSeen).toISOString() : ''
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `assets_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Assets exported.', 'success');
});

function updateAssetAlertCounts() {
    const alertCounts = {};
    timelineEvents.forEach(ev => {
        if (ev.src) alertCounts[ev.src] = (alertCounts[ev.src] || 0) + 1;
        if (ev.dst) alertCounts[ev.dst] = (alertCounts[ev.dst] || 0) + 1;
    });
    assets.forEach(asset => {
        const count = alertCounts[asset.ip] || 0;
        if (asset.alerts !== count) {
            asset.alerts = count;
            asset.lastSeen = Date.now();
        }
    });
    saveAssets();
    renderAssetsTable();
}
function updateUEBA() {
    if (globalPacketData.length === 0) return;
    const now = Date.now(); 

    
    const hostPackets = {};
    globalPacketData.forEach(pkt => {
        if (!pkt.src) return;
        if (!hostPackets[pkt.src]) hostPackets[pkt.src] = [];
        hostPackets[pkt.src].push(pkt);
    });

    let anomalousCount = 0;
    let totalScore = 0;
    let maxScore = 0;

    
    Object.keys(hostPackets).forEach(host => {
        const packets = hostPackets[host];
        const recent = packets.filter(p => (now - p.timestamp) < UEBA_WINDOW_MS);
        const historical = packets.filter(p => (now - p.timestamp) >= UEBA_WINDOW_MS && (now - p.timestamp) < UEBA_BASELINE_MS);

        
        if (historical.length < UEBA_MIN_SAMPLES) {
            const allExceptRecent = packets.filter(p => (now - p.timestamp) >= UEBA_WINDOW_MS);
            if (allExceptRecent.length < UEBA_MIN_SAMPLES) {
                
                if (!uebaData[host]) {
                    uebaData[host] = {
                        baseline: { destinations: new Set(), countries: new Set(), protocols: new Set(), ports: new Set(), packets: 0, bytes: 0, activeHours: null },
                        current: { destinations: new Set(), countries: new Set(), protocols: new Set(), ports: new Set(), packets: 0, bytes: 0, timestamps: [] },
                        anomalies: [],
                        score: 0,
                        timeline: [],
                        lastSeen: now,
                        riskLevel: 'Low',
                        asset: null,
                        cases: [],
                        iocMatches: [],
                        mitre: [],
                        automationStatus: 'OK'
                    };
                }
                return;
            }
            buildBaseline(host, allExceptRecent);
        } else {
            buildBaseline(host, historical);
        }

        
        const baselineData = uebaData[host]?.baseline || { destinations: new Set(), countries: new Set(), protocols: new Set(), ports: new Set(), packets: 0, bytes: 0, activeHours: null };
        const currentData = buildWindowData(recent);

        
        const anomalies = [];
        let score = 0;

        
        const baselineRate = baselineData.packets / (UEBA_BASELINE_MS / 60000);
        const currentRate = currentData.packets / (UEBA_WINDOW_MS / 60000);
        if (baselineRate > 0) {
            const ratio = currentRate / baselineRate;
            if (ratio > UEBA_THRESHOLDS.trafficVolume) {
                anomalies.push({
                    type: 'traffic_volume',
                    description: `Traffic volume ${Math.round(ratio)}x above baseline (${currentRate.toFixed(1)} vs ${baselineRate.toFixed(1)} pkts/min)`,
                    severity: ratio > 5 ? 'high' : 'medium',
                    details: { baselineRate, currentRate, ratio }
                });
                score += Math.min(ratio * 10, 40);
            }
        }

        
        const newDests = [...currentData.destinations].filter(d => !baselineData.destinations.has(d));
        if (newDests.length > UEBA_THRESHOLDS.newDestinations) {
            anomalies.push({
                type: 'new_destinations',
                description: `${newDests.length} new destinations: ${newDests.slice(0,5).join(', ')}${newDests.length>5?'...':''}`,
                severity: newDests.length > 10 ? 'high' : 'medium',
                details: { newDests }
            });
            score += Math.min(newDests.length * 5, 30);
        }

        
        const newProtocols = [...currentData.protocols].filter(p => !baselineData.protocols.has(p));
        if (newProtocols.length > UEBA_THRESHOLDS.rareProtocols) {
            anomalies.push({
                type: 'rare_protocols',
                description: `New protocols: ${newProtocols.join(', ')}`,
                severity: 'medium',
                details: { newProtocols }
            });
            score += newProtocols.length * 10;
        }

        
        if (currentData.countries.size > 0) {
            const newCountries = [...currentData.countries].filter(c => !baselineData.countries.has(c));
            if (newCountries.length > UEBA_THRESHOLDS.countryChange) {
                anomalies.push({
                    type: 'new_countries',
                    description: `Traffic to new countries: ${newCountries.join(', ')}`,
                    severity: newCountries.length > 3 ? 'high' : 'medium',
                    details: { newCountries }
                });
                score += newCountries.length * 8;
            }
        }

        
        const newPorts = [...currentData.ports].filter(p => !baselineData.ports.has(p));
        if (newPorts.length > 0) {
            anomalies.push({
                type: 'new_ports',
                description: `New ports: ${newPorts.join(', ')}`,
                severity: newPorts.length > 2 ? 'high' : 'medium',
                details: { newPorts },
                timestamp: now
            });
            score += newPorts.length * 5;
        }

        
        const beacon = detectBeaconing(currentData.timestamps);
        if (beacon) {
            anomalies.push({
                type: 'beaconing',
                description: beacon.description,
                severity: 'high',
                details: { interval: beacon.interval, count: beacon.count },
                timestamp: now
            });
            score += 25;
        }

        
        if (baselineData.activeHours) {
            const currentHours = currentData.timestamps.map(ts => new Date(ts).getHours());
            const outside = currentHours.some(h => h < baselineData.activeHours.start || h > baselineData.activeHours.end);
            if (outside && currentData.timestamps.length > 3) {
                anomalies.push({
                    type: 'outside_hours',
                    description: `Activity outside normal hours (${baselineData.activeHours.start}:00-${baselineData.activeHours.end}:00)`,
                    severity: 'medium',
                    details: { baselineStart: baselineData.activeHours.start, baselineEnd: baselineData.activeHours.end },
                    timestamp: now
                });
                score += 15;
            }
        }

        
        score = Math.min(score, 100);

        let riskLevel = 'Low';
        if (score >= 80) riskLevel = 'Critical';
        else if (score >= 50) riskLevel = 'High';
        else if (score >= 20) riskLevel = 'Medium';

        

        
        if (!uebaData[host]) {
            uebaData[host] = {
                baseline: baselineData,
                current: currentData,
                anomalies: anomalies,
                score: score,
                lastSeen: now,
                timeline: [],
                riskLevel: riskLevel,
                asset: null,
                cases: [],
                iocMatches: [],
                mitre: [],
                automationStatus: 'OK'
            };
        } else {
            uebaData[host].current = currentData;
            uebaData[host].baseline = baselineData;
            uebaData[host].anomalies = anomalies;
            uebaData[host].score = score;
            uebaData[host].riskLevel = riskLevel;
            uebaData[host].lastSeen = now;
            if (!uebaData[host].timeline) uebaData[host].timeline = [];
        }

        
        uebaData[host].timeline.push(...anomalies.map(a => ({ ...a, timestamp: formatAlertTime(a) || now })));
        if (uebaData[host].timeline.length > 100) uebaData[host].timeline = uebaData[host].timeline.slice(-100);

        if (score > 0) anomalousCount++;
        totalScore += score;
        if (score > maxScore) maxScore = score;
    });

    
    document.getElementById('ueba-total-hosts').textContent = Object.keys(hostPackets).length;
    document.getElementById('ueba-anomalous-hosts').textContent = anomalousCount;
    document.getElementById('ueba-avg-score').textContent = (totalScore / Object.keys(hostPackets).length || 0).toFixed(1);
    document.getElementById('ueba-max-score').textContent = maxScore.toFixed(1);

    renderUEBATable();
}

function buildBaseline(host, packets) {
    const data = {
        destinations: new Set(),
        countries: new Set(),
        protocols: new Set(),
        ports: new Set(),
        packets: packets.length,
        bytes: packets.reduce((sum, p) => sum + (p.size || 0), 0),
        activeHours: null
    };
    const timestamps = [];
    packets.forEach(p => {
        if (p.dst) data.destinations.add(p.dst);
        if (p.proto) data.protocols.add(p.proto);
        if (p.dst_port) data.ports.add(p.dst_port);
        if (p.timestamp) timestamps.push(p.timestamp);
        
        const dstGeo = geoCache.get(p.dst);
        if (dstGeo && dstGeo.code) data.countries.add(dstGeo.code);
    });
    
    if (timestamps.length > 3) {
        const hours = timestamps.map(ts => new Date(ts).getHours());
        const minHour = Math.min(...hours);
        const maxHour = Math.max(...hours);
        data.activeHours = { start: minHour, end: maxHour };
    }
    if (!uebaData[host]) uebaData[host] = {};
    uebaData[host].baseline = data;
}

function buildWindowData(packets) {
    const data = {
        destinations: new Set(),
        countries: new Set(),
        protocols: new Set(),
        ports: new Set(),
        packets: packets.length,
        bytes: packets.reduce((sum, p) => sum + (p.size || 0), 0),
        timestamps: []
    };
    packets.forEach(p => {
        if (p.dst) data.destinations.add(p.dst);
        if (p.proto) data.protocols.add(p.proto);
        if (p.dst_port) data.ports.add(p.dst_port);
        if (p.timestamp) data.timestamps.push(p.timestamp);
        const dstGeo = geoCache.get(p.dst);
        if (dstGeo && dstGeo.code) data.countries.add(dstGeo.code);
    });
    return data;

}function renderUEBATable() {
    const tbody = document.getElementById('ueba-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const hosts = Object.keys(uebaData);
    if (hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No behavioral data yet. Collecting baseline...</td></tr>';
        return;
    }
    
    const sorted = hosts.sort((a,b) => (uebaData[b].score || 0) - (uebaData[a].score || 0));
    sorted.forEach(host => {
        const data = uebaData[host];
        const score = data.score || 0;
        const anomalies = data.anomalies || [];
        const trafficVol = data.current?.packets || 0;
        const newDests = anomalies.filter(a => a.type === 'new_destinations').length;
        const rareProtos = anomalies.filter(a => a.type === 'rare_protocols').length;
        const riskLevel = data.riskLevel || 'Low';
        
        const row = document.createElement('tr');
        const scoreColor = score >= 80 ? '#ef4444' : score >= 50 ? '#f59e0b' : '#10b981';
        const riskBadge = `<span class="status-badge ${riskLevel === 'Critical' ? 'host-block' : riskLevel === 'High' ? 'host-alert' : 'host-ok'}">${riskLevel}</span>`;
        
        row.innerHTML = `
            <td><span class="ip-intel-trigger" data-ip="${host}">${host}</span></td>
            <td style="color:${scoreColor}; font-weight:600;">${score.toFixed(1)}</td>
            <td>${riskBadge}</td>
            <td>${anomalies.length}</td>
            <td>${trafficVol} pkts</td>
            <td>${newDests}</td>
            <td>${rareProtos}</td>
            <td>${data.lastSeen ? new Date(data.lastSeen).toLocaleTimeString() : '—'}</td>
            <td><button class="btn-action view-ueba-detail" data-host="${host}">Details</button></td>
        `;
        tbody.appendChild(row);
    });

    
    document.querySelectorAll('.view-ueba-detail').forEach(btn => {
        btn.addEventListener('click', function() {
            const host = this.dataset.host;
            openUEBADetail(host);
        });
    });
}

function openUEBADetail(host) {
    const data = uebaData[host];
    if (!data) {
        showToast('No data for this host.', 'warning');
        return;
    }
    const modal = document.getElementById('ueba-detail-modal');
    const title = document.getElementById('ueba-detail-title');
    const content = document.getElementById('ueba-detail-content');
    title.textContent = `UEBA - ${host}`;

    
    const asset = getAssetByIdentifier(host);
    
    const relatedCases = cases.filter(c => c.alerts && c.alerts.some(alertId => timelineEvents.some(e => e.id === alertId && (e.src === host || e.dst === host))));
    const relatedIOCs = iocs.filter(ioc => ioc.hits && ioc.hits.some(h => h.src === host || h.dst === host));
    const relatedMitre = new Set();
    timelineEvents.filter(e => e.src === host || e.dst === host).forEach(e => {
        if (e.mitre) relatedMitre.add(e.mitre);
    });
    const automationStatus = blockedIPs.has(host) ? 'Blocked' : quarantinedHosts.has(host) ? 'Quarantined' : 'Healthy';

    
    const timelineHtml = data.timeline.slice(-20).reverse().map(a => `
        <div style="padding:4px 8px; margin-bottom:4px; border-left:3px solid ${a.severity === 'high' ? '#ef4444' : a.severity === 'medium' ? '#f59e0b' : '#10b981'}; background:var(--surface-light); border-radius:4px;">
            <span style="font-size:12px; color:var(--text-muted);">${formatAlertTime(a)}</span>
            <strong>${a.type.replace('_',' ').toUpperCase()}</strong> (${a.severity})
            <div style="font-size:13px;">${a.description}</div>
        </div>
    `).join('') || '<p>No anomalies yet.</p>';

    const assetHtml = asset ? `
        <div style="background:var(--surface-light); padding:12px; border-radius:8px; margin-bottom:16px;">
            <strong>Asset:</strong> ${asset.hostname} (${asset.ip})<br>
            <strong>Owner:</strong> ${asset.owner} | <strong>Criticality:</strong> ${asset.criticality}<br>
            <strong>Risk:</strong> ${asset.risk.toFixed(1)} | <strong>Status:</strong> ${asset.status}
        </div>
    ` : '';

    let html = `
        ${assetHtml}
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;">
            <div><strong>Anomaly Score:</strong> ${data.score.toFixed(1)}</div>
            <div><strong>Risk Level:</strong> <span class="status-badge ${data.riskLevel === 'Critical' ? 'host-block' : data.riskLevel === 'High' ? 'host-alert' : 'host-ok'}">${data.riskLevel}</span></div>
            <div><strong>Anomalies:</strong> ${data.anomalies.length}</div>
            <div><strong>Automation:</strong> ${automationStatus}</div>
            <div><strong>Related Cases:</strong> ${relatedCases.length}</div>
            <div><strong>IOC Matches:</strong> ${relatedIOCs.length}</div>
            <div><strong>MITRE Techniques:</strong> ${[...relatedMitre].join(', ') || 'None'}</div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; background:var(--surface-light); padding:12px; border-radius:8px;">
            <div><strong>Baseline (24h):</strong></div>
            <div><strong>Current (5m):</strong></div>
            <div>Packets: ${data.baseline.packets}</div>
            <div>Packets: ${data.current.packets}</div>
            <div>Destinations: ${data.baseline.destinations.size}</div>
            <div>Destinations: ${data.current.destinations.size}</div>
            <div>Protocols: ${[...data.baseline.protocols].join(', ')}</div>
            <div>Protocols: ${[...data.current.protocols].join(', ')}</div>
            <div>Ports: ${[...data.baseline.ports].join(', ')}</div>
            <div>Ports: ${[...data.current.ports].join(', ')}</div>
            <div>Countries: ${[...data.baseline.countries].join(', ')}</div>
            <div>Countries: ${[...data.current.countries].join(', ')}</div>
            <div>Active Hours: ${data.baseline.activeHours ? data.baseline.activeHours.start + ':00-' + data.baseline.activeHours.end + ':00' : 'Unknown'}</div>
            <div>Beaconing: ${detectBeaconing(data.current.timestamps) ? 'Detected' : 'None'}</div>
        </div>
        <h4>Anomaly Timeline</h4>
        <div style="max-height:300px; overflow-y:auto; padding:8px; background:var(--dark); border-radius:8px;">
            ${timelineHtml}
        </div>
    `;
    content.innerHTML = html;
    modal.classList.remove('hidden');
}

document.getElementById('close-ueba-detail')?.addEventListener('click', () => {
    document.getElementById('ueba-detail-modal').classList.add('hidden');
});


let currentInvestigationAlertId = null;
let investigationNotesMap = {}; 



function computePredictionScore(alert) {
    const src = alert.src;
    const base = predictNextAttackStage(alert);
    let score = 0;
    const breakdown = [];

    
    const progressScore = Math.min(base.progress * 0.4, 40);
    score += progressScore;
    breakdown.push({ reason: 'Attack chain progress', contribution: progressScore });

    
    const confContrib = (alert.confidence || 50) * 0.2;
    score += confContrib;
    breakdown.push({ reason: 'Alert confidence', contribution: confContrib });

    
    const risk = mlInfoMap.get(src)?.score || 0;
    const riskContrib = Math.min(risk * 0.15, 15);
    score += riskContrib;
    breakdown.push({ reason: 'Host risk score', contribution: riskContrib });

    
    const ueba = uebaData[src]?.score || 0;
    const uebaContrib = Math.min(ueba * 0.15, 15);
    score += uebaContrib;
    breakdown.push({ reason: 'UEBA anomaly score', contribution: uebaContrib });

    
    let iocContrib = 0;
    if (alert.evidence && alert.evidence.iocType) {
        iocContrib = 15;
        breakdown.push({ reason: 'IOC correlation', contribution: iocContrib });
        score += iocContrib;
    } else {
        
        const srcInIOC = iocs.some(i => i.value === src);
        const dstInIOC = alert.dst && iocs.some(i => i.value === alert.dst);
        if (srcInIOC || dstInIOC) {
            iocContrib = 12;
            breakdown.push({ reason: 'IOC match', contribution: iocContrib });
            score += iocContrib;
        }
    }

    
    const hasAutoAction = actionLogs.some(l => l.alertId === alert.id && l.success);
    if (hasAutoAction) {
        const autoContrib = 10;
        breakdown.push({ reason: 'Automated action executed', contribution: autoContrib });
        score += autoContrib;
    }

    
    const prevAlerts = timelineEvents.filter(e => e.src === src && e.id !== alert.id).length;
    if (prevAlerts > 0) {
        const prevContrib = Math.min(prevAlerts * 2, 10);
        breakdown.push({ reason: `${prevAlerts} previous related alerts`, contribution: prevContrib });
        score += prevContrib;
    }

    
    score = Math.min(score, 100);

    
    const totalContrib = breakdown.reduce((sum, item) => sum + item.contribution, 0);
    if (totalContrib > 0) {
        const scale = score / totalContrib;
        breakdown.forEach(item => {
            item.contribution = Math.round(item.contribution * scale);
        });
        
        let sum = breakdown.reduce((s, item) => s + item.contribution, 0);
        if (sum !== score && breakdown.length > 0) {
            const diff = score - sum;
            breakdown[0].contribution += diff;
        }
    } else {
        breakdown.push({ reason: 'Base detection', contribution: score });
    }

    const level = score >= 80 ? 'High' : score >= 50 ? 'Medium' : 'Low';

    return {
        probability: score,
        level: level,
        breakdown: breakdown,
        nextPhase: base.nextPhase,
        currentPhase: base.currentPhase,
        completedPhases: base.completedPhases,
        progress: base.progress,
        reasoning: base.reasoning
    };
}




function openAlertInvestigation(alertId) {
    const alert = timelineEvents.find(e => e.id === alertId);
    if (!alert) {
        showToast('Alert not found.', 'danger');
        return;
    }
    currentInvestigationAlertId = alertId;
    if (!alert.investigationNotes) alert.investigationNotes = [];

    const modal = document.getElementById('alert-investigation-modal');
    const title = document.getElementById('alert-investigation-title');
    const content = document.getElementById('alert-investigation-content');
    title.textContent = `Investigation: ${alert.eventType}`;

    
    const src = alert.src;
    const dst = alert.dst;
    const now = Date.now();

    
    const relatedPacketIds = new Set();
    if (src && indices.packetsByHost.has(src)) {
        indices.packetsByHost.get(src).forEach(id => relatedPacketIds.add(id));
    }
    if (dst && indices.packetsByHost.has(dst)) {
        indices.packetsByHost.get(dst).forEach(id => relatedPacketIds.add(id));
    }
    const relatedPackets = globalPacketData.filter(p => relatedPacketIds.has(p.id));

    const srcAsset = getAssetByIdentifier(src);
    const dstAsset = getAssetByIdentifier(dst);
    const srcRisk = srcAsset ? srcAsset.risk : (mlInfoMap.get(src)?.score || 0);
    const dstRisk = dstAsset ? dstAsset.risk : (mlInfoMap.get(dst)?.score || 0);
    const srcUEBA = uebaData[src]?.score || 0;
    const dstUEBA = uebaData[dst]?.score || 0;

    const relatedCaseIds = new Set();
    if (indices.casesByAlert.has(alert.id)) {
        indices.casesByAlert.get(alert.id).forEach(id => relatedCaseIds.add(id));
    }
    const relatedCases = cases.filter(c => relatedCaseIds.has(c.id));

    const relatedIocIds = new Set();
    if (indices.iocsByAlert.has(alert.id)) {
        indices.iocsByAlert.get(alert.id).forEach(id => relatedIocIds.add(id));
    }
    const relatedIOCs = iocs.filter(ioc => relatedIocIds.has(ioc.id));

    const relatedActionIds = new Set();
    if (indices.actionsByAlert.has(alert.id)) {
        indices.actionsByAlert.get(alert.id).forEach(id => relatedActionIds.add(id));
    }
    const autoActions = actionLogs.filter(log => relatedActionIds.has(log.id));

    
    let detectionRule = 'Heuristic';
    let triggerReason = '';
    if (alert.source === 'IOC') detectionRule = 'IOC Match Rule';
    else if (alert.source === 'Rule' && alert.ruleName) {
        detectionRule = `Custom Rule: ${alert.ruleName} (ID: ${alert.ruleId})`;
    } else if (alert.source === 'Signature') detectionRule = 'Signature Rule';
    else if (alert.source === 'ML') detectionRule = 'Machine Learning';
    else if (alert.source === 'Automation') detectionRule = 'Automated Response';
    else detectionRule = 'Heuristic Engine';

    const triggerParts = [];
    if (alert.mitre) triggerParts.push(`MITRE ${alert.mitre}`);
    if (alert.source === 'IOC') triggerParts.push('IOC Match');
    if (alert.source === 'Signature') triggerParts.push('Signature Match');
    if (alert.source === 'Rule' && alert.ruleName) { triggerParts.push(`Rule: ${alert.ruleName}`); }
    if (alert.source === 'ML') triggerParts.push('ML Classification');
    if (alert.eventType.includes('Port Scan')) triggerParts.push('Port Scan Detected');
    if (alert.eventType.includes('Brute Force')) triggerParts.push('Brute Force Attempt');
    if (alert.eventType.includes('Beaconing')) triggerParts.push('Beaconing Detected');
    if (alert.eventType.includes('DNS Tunneling')) triggerParts.push('DNS Tunneling');
    if (alert.eventType.includes('Exfiltration')) triggerParts.push('Data Exfiltration');
    if (alert.eventType.includes('C2')) triggerParts.push('C2 Activity');
    if (alert.eventType.includes('Tor')) triggerParts.push('Tor Connection');
    if (alert.eventType.includes('Geo')) triggerParts.push('Suspicious Geolocation');
    if (alert.eventType.includes('Host Risk Change')) triggerParts.push('Risk Change');
    if (alert.eventType.includes('Blacklist')) triggerParts.push('Blacklist Match');
    triggerReason = triggerParts.join(', ') || 'Unknown';

    const chain = buildDetectionChain(alert);
    const history = getHostHistory(src);
    const confidenceReasons = buildConfidenceReasons(alert);

    const openedAt = alert.eventTimestamp || Date.now();
    let acknowledgedAt = alert.acknowledgedAt || null;
    let resolvedAt = alert.resolvedAt || null;
    let duration = null;
    if (acknowledgedAt) duration = Math.round((acknowledgedAt - openedAt) / 60000);
    else if (resolvedAt) duration = Math.round((resolvedAt - openedAt) / 60000);

    
    let explanationData = null;
    if (alert.explanation) {
        explanationData = {
            summary: alert.explanation[0] || alert.details,
            explanation: alert.explanation,
            confidenceBreakdown: [],
            whyNot100: [],
            aiModel: "Legacy Rule Engine",
            evidenceCount: alert.explanation.length || 0,
            mitreCount: alert.mitre ? 1 : 0,
            iocCount: 0
        };
    } else if (alert.evidence) {
        explanationData = generateAlertExplanation(alert);
    }

    
    const prediction = computePredictionScore(alert);

    
    const attackStage = getAttackStage(alert);
    const nextBehaviour = getNextBehaviour(alert);
    const impact = getPotentialImpact(alert);

    
    let html = '';

    
    html += `<div class="investigation-header" style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:16px; background:var(--surface-light); padding:12px; border-radius:8px;">`;
    html += `<div><strong>Severity:</strong> <span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span></div>`;
    html += `<div><strong>Confidence:</strong> ${alert.confidence || 50}%</div>`;
    html += `<div><strong>Time:</strong> ${formatAlertTime(alert)}</div>`;
    html += `<div><strong>Source:</strong> <span class="ip-intel-trigger" data-ip="${src}">${src}</span></div>`;
    html += `<div><strong>Destination:</strong> <span class="ip-intel-trigger" data-ip="${dst}">${dst}</span></div>`;
    html += `<div><strong>MITRE:</strong> ${alert.mitre ? `<a href="${MITRE_TECHNIQUES[alert.mitre]?.url || '#'}" target="_blank">${alert.mitre} (${MITRE_TECHNIQUES[alert.mitre]?.name || 'Unknown'})</a>` : '—'}</div>`;
    html += `<div><strong>Detection Rule:</strong> ${detectionRule}</div>`;
    html += `<div><strong>Trigger Reason:</strong> ${triggerReason}</div>`;
    html += `<div><strong>Opened:</strong> ${new Date(openedAt).toLocaleTimeString()}</div>`;
    if (acknowledgedAt) {
        html += `<div><strong>Acknowledged:</strong> ${new Date(acknowledgedAt).toLocaleTimeString()}</div>`;
    } else {
        html += `<div><strong>Acknowledged:</strong> —</div>`;
    }
    if (resolvedAt) {
        html += `<div><strong>Resolved:</strong> ${new Date(resolvedAt).toLocaleTimeString()}</div>`;
    } else {
        html += `<div><strong>Resolved:</strong> —</div>`;
    }
    if (duration !== null) html += `<div><strong>Investigation Time:</strong> ${duration} min${duration !== 1 ? 's' : ''}</div>`;
    html += `</div>`;

    
    if (explanationData) {
        const { summary, explanation, confidenceBreakdown, whyNot100, aiModel, evidenceCount, mitreCount, iocCount } = explanationData;
        const confidenceColor = alert.confidence >= 95 ? '#10b981' : alert.confidence >= 80 ? '#fbbf24' : '#ef4444';
        let evidenceCountStr = `${evidenceCount || explanation.length} behavioural indicator${(evidenceCount || explanation.length) !== 1 ? 's' : ''}`;
        if (mitreCount) evidenceCountStr += `, ${mitreCount} MITRE mapping${mitreCount !== 1 ? 's' : ''}`;
        if (iocCount) evidenceCountStr += `, ${iocCount} IOC correlation${iocCount !== 1 ? 's' : ''}`;

        html += `<div style="margin-bottom:16px;">`;
        html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; border-left: 4px solid var(--primary);">`;
        html += `<div style="display:flex; align-items:center; gap:12px; margin-bottom:8px;">`;
        html += `<i class="fas fa-brain" style="color:var(--primary); font-size:20px;"></i>`;
        html += `<span style="font-weight:600; font-size:16px;">AI Investigation Summary</span>`;
        html += `<span style="margin-left:auto; font-size:12px; color:var(--text-muted); background:var(--dark); padding:2px 10px; border-radius:12px;">${aiModel}</span>`;
        html += `</div>`;

        
        html += `<div style="margin-bottom:8px;">`;
        html += `<span style="font-weight:600; font-size:14px;">Assessment</span>`;
        html += `<p style="margin:4px 0 0 0; font-size:14px; line-height:1.5;">${summary || 'Alert generated based on security telemetry.'}</p>`;
        html += `</div>`;

        
        html += `<div style="display:flex; align-items:center; gap:12px; margin-top:8px;">`;
        html += `<span style="font-weight:600; font-size:14px;">Overall Confidence</span>`;
        html += `<span style="font-weight:700; font-size:18px; color:${confidenceColor};">${alert.confidence}%</span>`;
        html += `</div>`;

        
        if (explanation.length) {
            html += `<div style="margin-top:8px;">`;
            html += `<span style="font-weight:600; font-size:14px;">Primary Evidence</span>`;
            html += `<ul style="list-style: none; padding: 0; margin: 4px 0 0 0;">`;
            explanation.forEach(line => {
                html += `<li style="padding: 2px 0; font-size:14px;">✓ ${line}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        }

        
        if (confidenceBreakdown && confidenceBreakdown.length) {
            html += `<div style="margin-top:12px; background: var(--dark); padding: 12px; border-radius: 8px;">`;
            html += `<span style="font-weight:600; font-size:13px;">Confidence Breakdown</span>`;
            confidenceBreakdown.forEach(item => {
                html += `<div style="display:flex; justify-content:space-between; padding:2px 0; font-size:13px;">`;
                html += `<span>${item.reason}</span>`;
                html += `<span style="font-weight:600; color:var(--primary);">+${item.contribution}%</span>`;
                html += `</div>`;
            });
            html += `<hr style="border-color:var(--border); margin:4px 0;">`;
            html += `<div style="display:flex; justify-content:space-between; font-weight:700; font-size:15px;">`;
            html += `<span>Overall Confidence</span>`;
            html += `<span style="color:${confidenceColor};">${alert.confidence}%</span>`;
            html += `</div>`;
            html += `</div>`;
        }

        
        if (whyNot100 && whyNot100.length) {
            html += `<div style="margin-top:12px;">`;
            html += `<span style="font-weight:600; font-size:13px;">Why confidence isn't higher</span>`;
            html += `<ul style="list-style: none; padding: 0; margin: 4px 0 0 0;">`;
            whyNot100.forEach(line => {
                html += `<li style="font-size:13px; color:var(--text-muted); padding:2px 0;">• ${line}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        }

        html += `</div>`;
        html += `</div>`;
    } else {
        
        html += `<div style="margin-bottom:16px; background: var(--surface-light); padding: 12px; border-radius: 8px;">`;
        html += `<h4 style="margin:0;"><i class="fas fa-info-circle"></i> Detection Summary</h4>`;
        html += `<p style="margin:4px 0 0 0;">${alert.details}</p>`;
        html += `<div style="display:flex; gap:20px; margin-top:8px; font-size:14px;">`;
        html += `<div><strong>Confidence:</strong> ${alert.confidence}%</div>`;
        html += `<div><strong>Risk:</strong> ${alert.severity.toUpperCase()}</div>`;
        if (alert.mitre) html += `<div><strong>MITRE:</strong> ${alert.mitre}</div>`;
        html += `</div></div>`;
    }

const riskScoreData = computeAIRiskScore(alert);
const riskLevelColor = riskScoreData.level === 'Critical' ? '#ef4444' :
                       riskScoreData.level === 'High' ? '#f97316' :
                       riskScoreData.level === 'Elevated' ? '#f59e0b' :
                       riskScoreData.level === 'Moderate' ? '#fbbf24' :
                       riskScoreData.level === 'Low' ? '#10b981' : '#6b7280';

html += `<div style="margin-bottom:16px;">`;
html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; border-left: 4px solid ${riskLevelColor};">`;
html += `<div style="display:flex; align-items:center; gap:12px; margin-bottom:8px;">`;
html += `<i class="fas fa-shield-alt" style="color:${riskLevelColor}; font-size:20px;"></i>`;
html += `<span style="font-weight:600; font-size:16px;">AI Risk Score</span>`;
html += `<span style="margin-left:auto; font-weight:700; font-size:20px; color:${riskLevelColor};">${riskScoreData.score}</span>`;
html += `<span style="background:${riskLevelColor}; color:white; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600;">${riskScoreData.level}</span>`;
html += `</div>`;


html += `<div style="margin:8px 0 12px 0; padding:8px 12px; background:var(--dark); border-radius:6px;">`;
html += `<strong>Overall Assessment</strong><br>`;
html += `<span style="font-size:14px; color:var(--text-muted);">${riskScoreData.reasoning}</span>`;
html += `</div>`;


if (riskScoreData.breakdown && riskScoreData.breakdown.length) {
    html += `<div style="background: var(--dark); padding: 12px; border-radius: 8px;">`;
    html += `<span style="font-weight:600; font-size:13px;">Contributing Factors</span>`;
    const maxContrib = Math.max(...riskScoreData.breakdown.map(item => item.contribution), 1);
    riskScoreData.breakdown.forEach(item => {
        const barWidth = (item.contribution / maxContrib) * 100;
        html += `<div style="display:flex; align-items:center; gap:8px; padding:2px 0; font-size:13px;">`;
        html += `<span style="width:160px; flex-shrink:0;">${item.reason}</span>`;
        html += `<div style="flex:1; height:8px; background:var(--surface-light); border-radius:4px; overflow:hidden;">`;
        html += `<div style="width:${barWidth}%; height:100%; background:var(--primary); border-radius:4px;"></div>`;
        html += `</div>`;
        html += `<span style="font-weight:600; color:var(--primary); min-width:40px; text-align:right;">+${item.contribution}</span>`;
        html += `</div>`;
    });
    html += `</div>`;
}
html += `</div>`;
html += `</div>`;

    
    html += `<div style="margin-bottom:16px;">`;
    html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; border-left: 4px solid var(--warning);">`;
    html += `<div style="display:flex; align-items:center; gap:8px; margin-bottom:12px;">`;
    html += `<i class="fas fa-crosshairs" style="color:var(--warning);"></i>`;
    html += `<span style="font-weight:600; font-size:16px;">AI Attack Progress Assessment</span>`;
    html += `</div>`;

    
    html += `<div style="margin-bottom:12px;">`;
    html += `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:6px;">`;
    PHASE_ORDER.forEach(phase => {
        const done = prediction.completedPhases.includes(phase);
        const isCurrent = phase === prediction.currentPhase;
        const color = done ? 'var(--secondary)' : isCurrent ? 'var(--warning)' : 'var(--text-muted)';
        html += `<span style="padding:2px 8px; border-radius:12px; background:${color}20; border:1px solid ${color}; color:${color}; font-size:12px;">${done ? '✅' : isCurrent ? '⏳' : '○'} ${phase}</span>`;
    });
    html += `</div>`;
    const progressPct = Math.min(prediction.progress, 100);
    html += `<div style="width:100%; height:6px; background:var(--surface); border-radius:4px; overflow:hidden;">`;
    html += `<div style="width:${progressPct}%; height:100%; background:var(--primary); transition:width 0.6s;"></div>`;
    html += `</div>`;
    html += `<div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-muted);">`;
    html += `<span>${prediction.completedPhases.length} / ${PHASE_ORDER.length} phases</span>`;
    html += `<span>${Math.round(progressPct)}%</span>`;
    html += `</div>`;
    html += `</div>`;

    
    if (prediction.nextPhase !== 'Complete') {
        const levelColor = prediction.level === 'High' ? 'var(--secondary)' : prediction.level === 'Medium' ? 'var(--warning)' : 'var(--text-muted)';
        html += `<div style="display:flex; align-items:center; gap:12px; margin:12px 0;">`;
        html += `<span style="font-weight:600;">Predicted Next Stage</span>`;
        html += `<span style="font-size:18px; font-weight:700; color:var(--warning);">${prediction.nextPhase}</span>`;
        html += `<span style="background:${levelColor}; color:white; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600;">${prediction.level} (${Math.round(prediction.probability)}%)</span>`;
        html += `</div>`;
        
        if (prediction.breakdown && prediction.breakdown.length) {
            html += `<div style="background: var(--dark); padding: 12px; border-radius: 8px; margin: 8px 0;">`;
            html += `<span style="font-weight:600; font-size:13px;">Prediction Score Breakdown</span>`;
            prediction.breakdown.forEach(item => {
                html += `<div style="display:flex; justify-content:space-between; padding:2px 0; font-size:13px;">`;
                html += `<span>${item.reason}</span>`;
                html += `<span style="font-weight:600; color:var(--primary);">+${item.contribution}%</span>`;
                html += `</div>`;
            });
            html += `<hr style="border-color:var(--border); margin:4px 0;">`;
            html += `<div style="display:flex; justify-content:space-between; font-weight:700; font-size:15px;">`;
            html += `<span>Total Prediction Confidence</span>`;
            html += `<span style="color:${levelColor};">${Math.round(prediction.probability)}%</span>`;
            html += `</div>`;
            html += `</div>`;
        }
        
        if (prediction.reasoning && prediction.reasoning.length) {
            html += `<div style="font-size:13px; color:var(--text-muted); margin-top:4px;">`;
            prediction.reasoning.slice(0, 3).forEach(line => {
                html += `<div>• ${line}</div>`;
            });
            html += `</div>`;
        }
    } else {
        html += `<div style="margin:12px 0; font-weight:600; color:var(--secondary);">Attack chain complete – all stages observed.</div>`;
    }

    
    if (nextBehaviour.length) {
        html += `<div style="margin-top:12px;"><strong>Next likely attacker behaviour</strong></div>`;
        html += `<ul style="list-style: none; padding: 0; margin: 4px 0 0 0;">`;
        nextBehaviour.forEach(item => {
            html += `<li style="padding: 2px 0; font-size:14px;">• ${item}</li>`;
        });
        html += `</ul>`;
    }

    html += `</div>`;
    html += `</div>`;

    
    html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; margin-bottom: 12px; border-left: 4px solid ${impact.level === 'High' ? '#ef4444' : impact.level === 'Medium' ? '#f59e0b' : '#10b981'};">`;
    html += `<div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">`;
    html += `<i class="fas fa-exclamation-triangle" style="color:${impact.level === 'High' ? '#ef4444' : impact.level === 'Medium' ? '#f59e0b' : '#10b981'};"></i>`;
    html += `<span style="font-weight:600;">Potential Impact</span>`;
    html += `<span style="margin-left:auto; font-weight:700; color:${impact.level === 'High' ? '#ef4444' : impact.level === 'Medium' ? '#f59e0b' : '#10b981'};">${impact.level}</span>`;
    html += `</div>`;
    html += `<div style="font-size:14px; color:var(--text-muted);">`;
    impact.reasons.forEach(reason => {
        html += `<div>• ${reason}</div>`;
    });
    html += `</div>`;
    html += `</div>`;

    
    if (explanationData && explanationData.recommendedActions && explanationData.recommendedActions.length) {
        html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; margin-bottom: 12px;">`;
        html += `<div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">`;
        html += `<i class="fas fa-tasks" style="color:var(--warning);"></i>`;
        html += `<span style="font-weight:600;">Recommended Actions</span>`;
        html += `</div>`;
        html += `<ol style="margin:0; padding-left:20px;">`;
        explanationData.recommendedActions.forEach(action => {
            html += `<li style="font-size:14px; padding:4px 0; color:var(--text);">${action}</li>`;
        });
        html += `</ol>`;
        html += `</div>`;
    }

    
    html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; margin-bottom: 12px;">`;
    html += `<div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">`;
    html += `<i class="fas fa-link" style="color:var(--primary);"></i>`;
    html += `<span style="font-weight:600;">Related Investigation</span>`;
    html += `</div>`;
    html += `<div style="display:flex; flex-wrap:wrap; gap:8px;">`;
    if (src) {
        html += `<button class="btn-secondary btn-sm" onclick="document.getElementById('hunting-query-input').value='src:${src} OR dst:${src}'; switchView('hunting'); document.getElementById('hunting-run-btn').click();">🔍 Threat Hunt</button>`;
        html += `<button class="btn-secondary btn-sm" onclick="switchView('investigation');">🌐 Investigation Graph</button>`;
        html += `<button class="btn-secondary btn-sm" onclick="switchView('ueba');">📊 UEBA History</button>`;
        const asset = getAssetByIdentifier(src);
        if (asset) {
            html += `<button class="btn-secondary btn-sm" onclick="openAssetDetail(${asset.id})">🖥️ Asset Detail</button>`;
        }
    }
    if (dst) {
        html += `<button class="btn-secondary btn-sm" onclick="document.getElementById('hunting-query-input').value='src:${dst} OR dst:${dst}'; switchView('hunting'); document.getElementById('hunting-run-btn').click();">🔍 Hunt Destination</button>`;
    }
    html += `</div>`;
    html += `</div>`;

    
    
    
    
    

    
    html += `<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;">`;
    html += `<div style="background:var(--surface-light); padding:10px; border-radius:6px;">`;
    html += `<strong>Source Asset:</strong> ${srcAsset ? `${srcAsset.hostname}` : src}<br>`;
    html += `<strong>Risk Score:</strong> ${srcRisk.toFixed(1)} `;
    html += `<strong>UEBA:</strong> ${srcUEBA.toFixed(1)} `;
    html += `<strong>Status:</strong> ${srcAsset?.status || 'Unknown'}`;
    html += `</div>`;
    html += `<div style="background:var(--surface-light); padding:10px; border-radius:6px;">`;
    html += `<strong>Destination Asset:</strong> ${dstAsset ? `${dstAsset.hostname}` : dst}<br>`;
    html += `<strong>Risk Score:</strong> ${dstRisk.toFixed(1)} `;
    html += `<strong>UEBA:</strong> ${dstUEBA.toFixed(1)} `;
    html += `<strong>Status:</strong> ${dstAsset?.status || 'Unknown'}`;
    html += `</div>`;
    html += `</div>`;

    
    html += `<div style="margin-bottom:16px;"><strong>Detection Chain:</strong></div>`;
    html += `<div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px;">`;
    chain.forEach((step, idx) => {
        const color = step === 'Current Alert' ? 'var(--primary)' : 'var(--text-muted)';
        html += `<span style="background:var(--surface-light); padding:4px 12px; border-radius:12px; border:1px solid ${color}; color:${color};">${step}</span>`;
        if (idx < chain.length-1) html += `<span style="color:var(--text-muted);">→</span>`;
    });
    html += `</div>`;

    
    html += `<div style="margin-bottom:16px;"><strong>Confidence Explanation:</strong></div>`;
    html += `<ul style="list-style:none; padding:0; margin:0 0 16px 0;">`;
    confidenceReasons.forEach(reason => {
        html += `<li style="padding:4px 0; border-bottom:1px solid var(--border);">✅ ${reason}</li>`;
    });
    html += `</ul>`;

    
    html += `<div style="margin-bottom:16px;"><strong>Host History (${src}):</strong></div>`;
    html += `<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:16px;">`;
    html += `<div><strong>Previous Alerts:</strong> ${history.alerts}</div>`;
    html += `<div><strong>Previous Cases:</strong> ${history.cases}</div>`;
    html += `<div><strong>IOC Matches:</strong> ${history.iocs}</div>`;
    html += `</div>`;
    if (history.riskTrend && history.riskTrend.length > 1) {
        html += `<div style="margin-bottom:16px;"><strong>Risk Trend:</strong></div>`;
        html += `<canvas id="investigation-risk-spark" height="40" style="width:100%;"></canvas>`;
    }

    
    html += `<div style="margin-bottom:12px;"><strong>Related Cases:</strong> `;
    if (relatedCases.length) {
        html += relatedCases.map(c => `<span class="priority-badge" onclick="switchView('cases'); openCaseDetail(${c.id});">#${c.id} ${c.title}</span>`).join(' ');
    } else {
        html += 'None';
    }
    html += `</div>`;

    html += `<div style="margin-bottom:12px;"><strong>Related IOCs:</strong> `;
    if (relatedIOCs.length) {
        html += relatedIOCs.map(i => `<span class="ioc-type-badge" onclick="switchView('ioc'); showIocHits(${i.id});">${i.value}</span>`).join(' ');
    } else {
        html += 'None';
    }
    html += `</div>`;

    
    html += `<div style="margin-bottom:12px;"><strong>Automation Actions:</strong></div>`;
    if (autoActions.length) {
        html += `<div style="background:var(--dark); padding:8px; border-radius:6px; margin-bottom:16px;">`;
        autoActions.forEach(a => {
            html += `<div>${formatAlertTime(a)} – ${a.actionType} ${a.success ? '✅' : '❌'} (${a.message})</div>`;
        });
        html += `</div>`;
    } else {
        html += `<div style="margin-bottom:16px;">No automated actions.</div>`;
    }

    
    html += `<div style="margin-bottom:16px;"><strong>Manual Actions:</strong></div>`;
    html += `<div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px;">`;
    html += `<button class="btn-primary btn-sm" onclick="manualBlockIP('${src}')">🚫 Block IP</button>`;
    html += `<button class="btn-primary btn-sm" onclick="manualQuarantine('${src}')">🔒 Quarantine</button>`;
    html += `<button class="btn-secondary btn-sm" onclick="manualAddIOC('${src}')">➕ Add IOC</button>`;
    html += `<button class="btn-secondary btn-sm" onclick="manualCreateCase('${alert.id}')">📁 Create Case</button>`;
    html += `<button class="btn-warning btn-sm" onclick="manualEscalateSeverity('${alert.id}')">⬆️ Escalate</button>`;
    html += `<button class="btn-secondary btn-sm" onclick="manualAddNote('${alert.id}')">📝 Add Note</button>`;
    html += `<button class="btn-secondary btn-sm" onclick="createPolicyFromLastAction()">⚙️ Create Policy</button>`;
    html += `</div>`;

    
    html += `<div style="margin-bottom:16px;"><strong>Investigation Notes:</strong></div>`;
    html += `<div style="max-height:150px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; padding:8px; margin-bottom:12px;">`;
    if (alert.investigationNotes && alert.investigationNotes.length) {
        alert.investigationNotes.forEach(note => {
            html += `<div style="padding:4px 0; border-bottom:1px solid var(--border);">${new Date(note.timestamp).toLocaleString()}: ${note.text}</div>`;
        });
    } else {
        html += `<div class="text-muted">No notes yet.</div>`;
    }
    html += `</div>`;
    html += `<div style="display:flex; gap:8px; margin-bottom:16px;">`;
    html += `<input type="text" id="investigation-note-input" class="modal-input" placeholder="Add a note..." style="flex:1;">`;
    html += `<button class="btn-secondary" onclick="addInvestigationNote('${alert.id}')">Add Note</button>`;
    html += `</div>`;

    
    const timelineEventsRelated = timelineEvents
        .filter(e => e.src === src || e.dst === src || e.src === dst || e.dst === dst)
        .sort((a,b) => (b.eventTimestamp || 0) - (a.eventTimestamp || 0))
        .slice(0, 20);

    html += `<div style="margin-bottom:12px;"><strong>Related Timeline (${timelineEventsRelated.length} events):</strong></div>`;
    html += `<div style="max-height:200px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; padding:8px; margin-bottom:16px;">`;
    timelineEventsRelated.forEach(e => {
        const isCurrent = e.id === alert.id;
        html += `<div style="padding:4px 0; ${isCurrent ? 'background:var(--primary-dark);' : ''}">`;
        html += `<span style="color:var(--text-muted);">${formatAlertTime(e)}</span> `;
        html += `<span class="severity-${e.severity}">${e.severity.toUpperCase()}</span> `;
        html += `<strong>${e.eventType}</strong> ${e.src ? `(${e.src} → ${e.dst})` : ''}`;
        if (isCurrent) html += ` <span style="color:var(--primary);">← current</span>`;
        html += `</div>`;
    });
    html += `</div>`;

    
    html += `<div style="margin-bottom:12px;"><strong>Packet Evidence (${relatedPackets.length} packets):</strong></div>`;
    if (relatedPackets.length === 0) {
        html += `<p class="text-muted">No packets found.</p>`;
    } else {
        html += `<div style="max-height:200px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; margin-bottom:16px;">`;
        html += `<table style="width:100%; font-size:12px;"><thead><tr><th>Time</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Payload</th><th>Raw</th></tr></thead><tbody>`;
        relatedPackets.slice(0, 20).forEach(p => {
            const payload = p.payload ? sanitize(p.payload).slice(0, 40) : '—';
            const rawBtn = p.payload ? `<button class="btn-text btn-sm" onclick="showRawPacket('${encodeURIComponent(p.payload)}')">📄</button>` : '—';
            html += `<tr><td>${p.time}</td><td>${p.src}</td><td>${p.dst}</td><td>${p.proto}</td><td>${p.dst_port || 'any'}</td><td>${payload}</td><td>${rawBtn}</td></tr>`;
        });
        html += `</tbody></table></div>`;
    }

    
    html += `<div style="margin-bottom:12px;"><strong>Mini Investigation Graph:</strong></div>`;
    html += `<div style="display:flex; flex-wrap:wrap; gap:8px; padding:8px; background:var(--dark); border-radius:6px; margin-bottom:16px;">`;
    const graphNodes = getInvestigationGraphNodes(alert);
    graphNodes.forEach((node, idx) => {
        html += `<span style="background:var(--surface-light); padding:4px 12px; border-radius:12px; border:1px solid var(--border);">${node}</span>`;
        if (idx < graphNodes.length-1) html += `<span style="color:var(--text-muted);">→</span>`;
    });
    html += `</div>`;
    html += `<div style="margin-bottom:16px;"><button class="btn-secondary" onclick="switchView('investigation');">🔍 Expand Investigation Graph</button></div>`;

    
    html += `<div class="investigation-actions" style="margin-top:20px; display:flex; gap:12px; flex-wrap:wrap;">`;
    html += `<button class="btn-secondary" onclick="showPacketDrilldown('${alert.id}')"><i class="fas fa-search"></i> Packet Drilldown</button>`;
    if (src) {
        html += `<button class="btn-secondary" onclick="document.getElementById('hunting-query-input').value='src:${src} OR dst:${src}'; switchView('hunting'); document.getElementById('hunting-run-btn').click();"><i class="fas fa-search"></i> Hunt Source</button>`;
    }
    if (dst) {
        html += `<button class="btn-secondary" onclick="document.getElementById('hunting-query-input').value='src:${dst} OR dst:${dst}'; switchView('hunting'); document.getElementById('hunting-run-btn').click();"><i class="fas fa-search"></i> Hunt Destination</button>`;
    }
    if (alert.status === 'open') {
        html += `<button class="btn-primary" onclick="updateAlertStatus('${alert.id}', 'investigating'); openAlertInvestigation('${alert.id}');"><i class="fas fa-user-check"></i> Acknowledge</button>`;
        html += `<button class="btn-action fp" onclick="showFpModal('${alert.id}')"><i class="fas fa-flag"></i> False Positive</button>`;
    } else if (alert.status === 'investigating') {
        html += `<button class="btn-primary" onclick="updateAlertStatus('${alert.id}', 'resolved'); openAlertInvestigation('${alert.id}');"><i class="fas fa-check"></i> Resolve</button>`;
    }
    html += `<button class="btn-secondary" onclick="openAlertInvestigation('${alert.id}')"><i class="fas fa-sync"></i> Refresh</button>`;
    html += `</div>`;

    content.innerHTML = html;
    modal.classList.remove('hidden');

    
    if (history.riskTrend && history.riskTrend.length > 1) {
        setTimeout(() => {
            const canvas = document.getElementById('investigation-risk-spark');
            if (canvas) {
                const ctx = canvas.getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: history.riskTrend.map((_,i) => i+1),
                        datasets: [{
                            data: history.riskTrend,
                            borderColor: '#6366f1',
                            borderWidth: 2,
                            pointRadius: 2,
                            fill: false
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: { x: { display: false }, y: { beginAtZero: true } }
                    }
                });
            }
        }, 100);
    }

    currentInvestigationAlertId = alertId;
}

function buildDetectionChain(alert) {
    const chain = [];
    const src = alert.src;
    if (src && hostStages.has(src)) {
        const stages = hostStages.get(src).stages;
        const stageMap = {
            'scan': 'Recon',
            'geo': 'Recon',
            'access': 'Initial Access',
            'c2': 'C2',
            'dns_tunnel': 'DNS Tunneling',
            'tor': 'Tor',
            'exfil': 'Exfiltration'
        };
        const order = ['Recon', 'Initial Access', 'C2', 'DNS Tunneling', 'Tor', 'Exfiltration'];
        const present = new Set();
        for (const [stage, ts] of stages) {
            const phase = stageMap[stage] || stage;
            present.add(phase);
        }
        for (const phase of order) {
            if (present.has(phase)) chain.push(phase);
        }
    }
    
    chain.push('Current Alert');
    
    const autoActions = actionLogs.filter(log => log.alertId === alert.id);
    if (autoActions.length) chain.push('Automation');
    
    const relatedCases = cases.filter(c => c.alerts && c.alerts.includes(alert.id));
    if (relatedCases.length) chain.push('Case Created');
    return chain;
}

function getHostHistory(ip) {
    const alerts = timelineEvents.filter(e => e.src === ip || e.dst === ip);
    const casesRelated = cases.filter(c => c.alerts && c.alerts.some(alertId => alerts.some(a => a.id === alertId)));
    const iocsRelated = iocs.filter(ioc => ioc.hits && ioc.hits.some(h => h.src === ip || h.dst === ip));
    
    const asset = getAssetByIdentifier(ip);
    const riskTrend = asset?.riskHistory ? asset.riskHistory.map(h => h.score) : [0];
    return {
        alerts: alerts.length,
        cases: casesRelated.length,
        iocs: iocsRelated.length,
        riskTrend: riskTrend
    };
}

function buildConfidenceReasons(alert) {
    const reasons = [];
    
    if (alert.confidence >= 80) reasons.push('High confidence score');
    else if (alert.confidence >= 50) reasons.push('Medium confidence score');

    
    if (alert.mitre) reasons.push(`MITRE technique ${alert.mitre} mapped`);

    
    if (alert.src) {
        const asset = getAssetByIdentifier(alert.src);
        if (asset && asset.risk >= 80) reasons.push('Source is high-risk asset');
        if (asset && asset.criticality === 'Critical') reasons.push('Source is critical asset');
        if (uebaData[alert.src]?.score >= 50) reasons.push('UEBA anomaly for source');
    }

    
    if (alert.dst) {
        const asset = getAssetByIdentifier(alert.dst);
        if (asset && asset.risk >= 80) reasons.push('Destination is high-risk asset');
        if (blockedIPs.has(alert.dst)) reasons.push('Destination is blocked/IOC');
        if (uebaData[alert.dst]?.score >= 50) reasons.push('UEBA anomaly for destination');
    }

    
    if (alert.eventType.includes('IOC')) reasons.push('IOC match');
    if (alert.eventType.includes('Beaconing')) reasons.push('Beaconing detected');
    if (alert.eventType.includes('Exfiltration')) reasons.push('Data exfiltration pattern');
    if (alert.eventType.includes('C2')) reasons.push('C2 communication pattern');
    if (alert.eventType.includes('Brute Force')) reasons.push('Brute force attempts');
    if (alert.eventType.includes('Port Scan')) reasons.push('Port scanning behavior');
    if (alert.eventType.includes('Geo')) reasons.push('Suspicious geolocation');

    
    if (reasons.length === 0) reasons.push('Standard heuristic detection');
    return reasons;
}

function getInvestigationGraphNodes(alert) {
    const nodes = [];
    const src = alert.src;
    const dst = alert.dst;
    if (src) nodes.push(`Host: ${src}`);
    if (dst) nodes.push(`Dest: ${dst}`);
    if (alert.mitre) nodes.push(`MITRE: ${alert.mitre}`);
    
    const iocsRelated = iocs.filter(ioc => ioc.alertIds && ioc.alertIds.includes(alert.id));
    if (iocsRelated.length) nodes.push(`IOC: ${iocsRelated[0].value}`);
    
    const casesRelated = cases.filter(c => c.alerts && c.alerts.includes(alert.id));
    if (casesRelated.length) nodes.push(`Case #${casesRelated[0].id}`);
    
    const autoActions = actionLogs.filter(log => log.alertId === alert.id);
    if (autoActions.length) nodes.push('Automation');
    return nodes;
}

function manualBlockIP(ip) {
   console.log("manualBlockIP called for", ip);
    if (!ip) return;
    showConfirmModal(
        'Block IP',
        `Are you sure you want to block IP ${ip}?`,
        () => {
            if (!blockedIPs.has(ip)) {
                blockedIPs.add(ip);
                sendBlockedIPsToBackend();
                showToast(`Blocked IP ${ip}`, 'success');
                
                lastManualAction = { type: 'block_ip', target: ip, params: { targetIp: ip } };
                
                addInvestigationNote(currentInvestigationAlertId, `Manually blocked IP ${ip}`);
                
                addHighlightedActionLog('block_ip', ip, `Manually blocked IP ${ip}`);
                refreshInvestigationModal();
            } else {
                showToast('IP already blocked.', 'info');
            }
        }
    );
}

function manualQuarantine(host) {
   console.log("manualQuarantine called for", host);
    if (!host) return;
    showConfirmModal(
        'Quarantine Host',
        `Are you sure you want to quarantine host ${host}?`,
        () => {
            if (!quarantinedHosts.has(host)) {
                quarantinedHosts.add(host);
                showToast(`Quarantined host ${host}`, 'success');
                lastManualAction = { type: 'quarantine_host', target: host, params: { targetHost: host } };
                addInvestigationNote(currentInvestigationAlertId, `Manually quarantined host ${host}`);
                addHighlightedActionLog('quarantine_host', host, `Manually quarantined host ${host}`);
                refreshInvestigationModal();
            } else {
                showToast('Host already quarantined.', 'info');
            }
        }
    );
}
function manualAddIOC(value) {
    if (!value) return;
    const ioc = addIOC('ip', value, `Manually added from alert investigation`, 'high', null, false);
    showToast(`IOC ${value} added.`, 'success');
    addInvestigationNote(currentInvestigationAlertId, `Manually added IOC ${value}`);
    refreshInvestigationModal();
}

function manualCreateCase(alertId) {
    createCaseFromAlert(alertId);
    addInvestigationNote(currentInvestigationAlertId, `Created case from alert`);
    refreshInvestigationModal();
}

function manualEscalateSeverity(alertId) {
    const alert = timelineEvents.find(e => e.id === alertId);
    if (!alert) return;
    if (alert.severity !== 'critical') {
        alert.severity = 'critical';
        showToast('Severity escalated to critical.', 'warning');
        addInvestigationNote(currentInvestigationAlertId, 'Escalated severity to critical');
        refreshInvestigationModal();
    } else {
        showToast('Already critical.', 'info');
    }
}

function manualAddNote(alertId) {
    const input = document.getElementById('investigation-note-input');
    if (input) {
        input.focus();
    } else {
        
        const note = prompt('Enter note:');
        if (note) addInvestigationNote(alertId, note);
    }
}

function addInvestigationNote(alertId, text = null) {
    const input = document.getElementById('investigation-note-input');
    const noteText = text || input?.value.trim();
    if (!noteText) {
        showToast('Please enter a note.', 'warning');
        return;
    }
    const alert = timelineEvents.find(e => e.id === alertId);
    if (!alert) {
        showToast('Alert not found.', 'danger');
        return;
    }
    if (!alert.investigationNotes) alert.investigationNotes = [];
    alert.investigationNotes.push({ timestamp: Date.now(), text: noteText });
    if (input) input.value = '';
    refreshInvestigationModal();
    showToast('Note added.', 'success');
}

function refreshInvestigationModal() {
    if (currentInvestigationAlertId) {
        openAlertInvestigation(currentInvestigationAlertId);
    }
}

function showRawPacket(encodedPayload) {
    const payload = decodeURIComponent(encodedPayload);
    
    const modal = document.getElementById('payload-modal');
    const content = document.getElementById('payload-content');
    if (!modal || !content) return;

    
    const bytes = [];
    for (let i = 0; i < payload.length; i++) {
        bytes.push(payload.charCodeAt(i));
    }
    let hex = '';
    let ascii = '';
    for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i+16);
        const hexPart = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const asciiPart = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        hex += `${i.toString(16).padStart(8, '0')}: ${hexPart.padEnd(48, ' ')} ${asciiPart}\n`;
    }
    content.textContent = `Hex Dump:\n${hex}\n\nASCII:\n${payload}`;
    modal.classList.remove('hidden');
}


document.getElementById('close-alert-investigation')?.addEventListener('click', () => {
    document.getElementById('alert-investigation-modal').classList.add('hidden');
    currentInvestigationAlertId = null;
});
document.getElementById('alert-investigation-modal')?.addEventListener('click', function(e) {
    if (e.target === this) {
        this.classList.add('hidden');
        currentInvestigationAlertId = null;
    }
});

document.getElementById('close-raw-modal')?.addEventListener('click', () => {
    document.getElementById('raw-packet-modal').classList.add('hidden');
});
document.getElementById('raw-packet-modal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
});

function showRawPacketView(packet) {
    const modal = document.getElementById('raw-packet-modal');
    const content = document.getElementById('raw-packet-content');
    if (!modal || !content) return;

    
    function toHexDump(str, bytesPerLine = 16) {
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
            bytes.push(str.charCodeAt(i));
        }
        let lines = [];
        for (let i = 0; i < bytes.length; i += bytesPerLine) {
            const chunk = bytes.slice(i, i + bytesPerLine);
            const hex = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
            const ascii = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
            lines.push({ offset: i, hex: hex.padEnd(bytesPerLine * 3, ' '), ascii });
        }
        return lines;
    }

    
    const src = packet.src || '0.0.0.0';
    const dst = packet.dst || '0.0.0.0';
    const proto = packet.proto || 'Unknown';
    const srcPort = packet.src_port || '?';
    const dstPort = packet.dst_port || '?';
    const payload = packet.payload || '';

    
    const protoNum = {
        'TCP': 6,
        'UDP': 17,
        'ICMP': 1
    }[proto] || 0;

    
    const ethSrc = '00:11:22:33:44:55';
    const ethDst = 'aa:bb:cc:dd:ee:ff';
    const ethType = (proto === 'IPv6') ? '0x86dd' : '0x0800';

    
    const ipVer = 4;
    const ipHdrLen = 20;
    const ipTos = 0;
    const ipTotalLen = 20 + (payload.length || 0);
    const ipId = 0x1234;
    const ipFlags = 0x4000; 
    const ipTtl = 64;
    const ipProto = protoNum;
    const ipChecksum = 0x0000;
    const ipSrc = src;
    const ipDst = dst;

    
    let transport = '';
    let tcpFlags = '----';
    let seq = 0;
    let ack = 0;
    if (proto === 'TCP') {
        tcpFlags = 'SYN, ACK'; 
        seq = 0x12345678;
        ack = 0x87654321;
        transport = `
            <tr><td>Source Port</td><td>${srcPort}</td></tr>
            <tr><td>Destination Port</td><td>${dstPort}</td></tr>
            <tr><td>Sequence Number</td><td>${seq.toString(16).toUpperCase()}</td></tr>
            <tr><td>Acknowledgment Number</td><td>${ack.toString(16).toUpperCase()}</td></tr>
            <tr><td>Flags</td><td>${tcpFlags}</td></tr>
            <tr><td>Window Size</td><td>65535</td></tr>
            <tr><td>Checksum</td><td>0x0000</td></tr>
        `;
    } else if (proto === 'UDP') {
        transport = `
            <tr><td>Source Port</td><td>${srcPort}</td></tr>
            <tr><td>Destination Port</td><td>${dstPort}</td></tr>
            <tr><td>Length</td><td>${8 + payload.length}</td></tr>
            <tr><td>Checksum</td><td>0x0000</td></tr>
        `;
    } else if (proto === 'ICMP') {
        transport = `
            <tr><td>Type</td><td>8 (Echo Request)</td></tr>
            <tr><td>Code</td><td>0</td></tr>
            <tr><td>Checksum</td><td>0x0000</td></tr>
        `;
    } else {
        transport = `<tr><td colspan="2">Unknown transport protocol</td></tr>`;
    }

    
    const hexLines = toHexDump(payload);

    
    let html = `
        <div style="font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.6;">
            <h4>Ethernet Header</h4>
            <table class="raw-packet-table">
                <tr><td>Destination MAC</td><td>${ethDst}</td></tr>
                <tr><td>Source MAC</td><td>${ethSrc}</td></tr>
                <tr><td>Type</td><td>${ethType}</td></tr>
            </table>

            <h4 style="margin-top: 16px;">IP Header</h4>
            <table class="raw-packet-table">
                <tr><td>Version</td><td>${ipVer}</td></tr>
                <tr><td>Header Length</td><td>${ipHdrLen} bytes</td></tr>
                <tr><td>Type of Service</td><td>0x${ipTos.toString(16).padStart(2,'0')}</td></tr>
                <tr><td>Total Length</td><td>${ipTotalLen}</td></tr>
                <tr><td>Identification</td><td>0x${ipId.toString(16).toUpperCase()}</td></tr>
                <tr><td>Flags</td><td>0x${ipFlags.toString(16).toUpperCase()}</td></tr>
                <tr><td>Time to Live</td><td>${ipTtl}</td></tr>
                <tr><td>Protocol</td><td>${proto} (${ipProto})</td></tr>
                <tr><td>Checksum</td><td>0x${ipChecksum.toString(16).padStart(4,'0').toUpperCase()}</td></tr>
                <tr><td>Source IP</td><td>${ipSrc}</td></tr>
                <tr><td>Destination IP</td><td>${ipDst}</td></tr>
            </table>

            <h4 style="margin-top: 16px;">Transport Layer (${proto})</h4>
            <table class="raw-packet-table">
                ${transport}
            </table>

            <h4 style="margin-top: 16px;">Payload</h4>
            <pre style="background: var(--dark); padding: 12px; border-radius: 8px; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;">${escapeHtml(payload) || '(empty)'}</pre>

            <h4 style="margin-top: 16px;">Hex Dump</h4>
            <div style="background: var(--dark); padding: 12px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-size: 12px;">
                <table style="font-family: monospace; width: 100%; border-collapse: collapse;">
                    <tr><th style="text-align: left; padding-right: 16px;">Offset</th><th style="text-align: left; padding-right: 16px;">Hex</th><th style="text-align: left;">ASCII</th></tr>
                    ${hexLines.map(line => `
                        <tr>
                            <td style="padding-right: 16px;">${line.offset.toString(16).padStart(4,'0')}</td>
                            <td style="padding-right: 16px; font-family: monospace;">${line.hex}</td>
                            <td style="font-family: monospace;">${line.ascii}</td>
                        </tr>
                    `).join('')}
                </table>
            </div>

            <div style="margin-top: 16px;">
                <button class="btn-secondary" onclick="copyRawPacket()"><i class="fas fa-copy"></i> Copy as Text</button>
            </div>
        </div>
    `;

    content.innerHTML = html;
    modal.classList.remove('hidden');

    
    window._rawPacketData = { src, dst, proto, srcPort, dstPort, payload, hexLines };
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function copyRawPacket() {
    const data = window._rawPacketData;
    if (!data) return;
    let text = `--- Raw Packet ---\n`;
    text += `Source: ${data.src}:${data.srcPort}\nDestination: ${data.dst}:${data.dstPort}\nProtocol: ${data.proto}\n\nPayload:\n${data.payload || '(empty)'}\n\nHex Dump:\n`;
    data.hexLines.forEach(line => {
        text += `${line.offset.toString(16).padStart(4,'0')}: ${line.hex}  ${line.ascii}\n`;
    });
    navigator.clipboard.writeText(text).then(() => {
        showToast('Raw packet copied to clipboard.', 'success');
    }).catch(() => {
        
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Raw packet copied to clipboard.', 'success');
    });
}

document.getElementById('packet-raw-btn')?.addEventListener('click', () => {
    if (selectedPacketId) {
        const pkt = globalPacketData.find(p => p.id === selectedPacketId);
        if (pkt) {
            showRawPacketView(pkt);
        }
        actionMenu.classList.add('hidden');
    }
});

const CORRELATION_WINDOW_MS = 30 * 60 * 1000; 

function correlateAlerts() {
    const unassigned = timelineEvents.filter(e => (e.status === 'open' || e.status === 'investigating') && !e.incidentId);
    if (unassigned.length < 2) return;

    
    const groups = new Map(); 
    unassigned.forEach(alert => {
        const host = alert.src || alert.dst || 'unknown';
        if (!groups.has(host)) groups.set(host, []);
        groups.get(host).push(alert);
    });

    for (const [host, alerts] of groups) {
        if (alerts.length < 2) continue;
        alerts.sort((a,b) => a.eventTimestamp - b.eventTimestamp);
        let currentGroup = [alerts[0]];
        for (let i = 1; i < alerts.length; i++) {
            const prev = alerts[i-1];
            const curr = alerts[i];
            const score = computeCorrelationScore(prev, curr);
            if (score >= 70) {
                currentGroup.push(curr);
            } else {
                
                if (currentGroup.length >= 2) createIncidentFromAlerts(currentGroup);
                currentGroup = [curr];
            }
        }
        if (currentGroup.length >= 2) createIncidentFromAlerts(currentGroup);
    }
}

function computeIncidentConfidence(alerts) {
    let score = 0;
    const breakdown = [];

    
    const avgAlertConf = alerts.reduce((s, a) => s + (a.confidence || 50), 0) / alerts.length;
    score += avgAlertConf * 0.25;
    breakdown.push({ reason: 'Alert confidences', contribution: avgAlertConf * 0.25 });

    
    const stages = new Set(alerts.map(a => PHASE_MAP[STAGE_MAP[a.eventType]]).filter(Boolean));
    const progress = stages.size / PHASE_ORDER.length;
    score += progress * 20;
    breakdown.push({ reason: 'Kill chain progression', contribution: progress * 20 });

    
    const hasIOC = alerts.some(a => a.evidence?.iocType);
    if (hasIOC) {
        score += 20;
        breakdown.push({ reason: 'IOC correlation', contribution: 20 });
    }

    
    const uebaScores = alerts.map(a => uebaData[a.src]?.score || 0);
    const maxUeba = Math.max(...uebaScores, 0);
    const uebaContrib = Math.min(maxUeba * 0.18, 18);
    score += uebaContrib;
    breakdown.push({ reason: 'UEBA anomaly', contribution: uebaContrib });

    
    const hostRisks = alerts.map(a => mlInfoMap.get(a.src)?.score || 0);
    const maxRisk = Math.max(...hostRisks, 0);
    const riskContrib = Math.min(maxRisk * 0.15, 15);
    score += riskContrib;
    breakdown.push({ reason: 'Host risk', contribution: riskContrib });

    
    const sources = new Set(alerts.map(a => a.source).filter(Boolean));
    const sourceBonus = Math.min(sources.size * 2, 10);
    score += sourceBonus;
    breakdown.push({ reason: `${sources.size} detection engines`, contribution: sourceBonus });

    
    const hasAuto = alerts.some(a => actionLogs.some(l => l.alertId === a.id && l.success));
    if (hasAuto) {
        score += 7;
        breakdown.push({ reason: 'Automation response triggered', contribution: 7 });
    }

    
    score = Math.min(score, 100);
    
    const total = breakdown.reduce((s, b) => s + b.contribution, 0);
    if (total > 0) {
        const scale = score / total;
        breakdown.forEach(b => b.contribution = Math.round(b.contribution * scale));
        
        let sum = breakdown.reduce((s, b) => s + b.contribution, 0);
        if (sum !== score && breakdown.length) breakdown[0].contribution += score - sum;
    }
    return { score: Math.round(score), breakdown };
}

function createIncidentFromAlerts(alertGroup) {
    
    let severity = 'low';
    let confidenceSum = 0;
    const hosts = new Set();
    const attackStages = new Set();
    const alertIds = new Set();
    const timeline = [];

    alertGroup.forEach(alert => {
        
        if (alert.severity === 'critical') severity = 'critical';
        else if (alert.severity === 'high' && severity !== 'critical') severity = 'high';
        else if (alert.severity === 'medium' && severity !== 'critical' && severity !== 'high') severity = 'medium';
        
        confidenceSum += (alert.confidence || 50);
        
        if (alert.src) hosts.add(alert.src);
        if (alert.dst) hosts.add(alert.dst);
        
        const stage = STAGE_MAP[alert.eventType] || alert.eventType;
        const phase = PHASE_MAP[stage];
        if (phase) attackStages.add(phase);
        
        alertIds.add(alert.id);
        
        timeline.push({
        timestamp: alert.eventTimestamp || Date.now(),
        eventType: alert.eventType,
        details: alert.details,
        severity: alert.severity,
        alertId: alert.id,
        confidence: alert.confidence,
        source: alert.source || 'heuristic',
        evidence: alert.evidence || null,
    });
        
    });

    
    timeline.sort((a, b) => a.timestamp - b.timestamp);

    
    const hostList = [...hosts].join(', ');
    const title = `Incident: ${hostList} (${alertGroup.length} alerts)`;

    const avgConfidence = Math.round(confidenceSum / alertGroup.length);

    const incident = {
        id: nextIncidentId++,
        title,
        severity,
        status: 'open',
        hosts: new Set(hosts),
        alertIds: new Set(alertIds),
        timeline,
        attackStages,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        resolvedAt: null,
        confidence: avgConfidence,
        assignedTo: null,
        notes: [],
    };

    incident.correlationReason = computeCorrelationReason(alertGroup);
    const confidenceResult = computeIncidentConfidence(alertGroup);
    incident.confidenceBreakdown = confidenceResult.breakdown;
    incident.confidence = confidenceResult.score;

    incidents.push(incident);
    saveIncidents();

    alertGroup.forEach(alert => {
        alert.incidentId = incident.id;
        if (alert.status === 'open') alert.status = 'investigating';
    });

    renderIncidentsTable();
    updateIncidentStats();
    showToast(`🚨 Incident #${incident.id} created (${alertGroup.length} alerts)`, 'warning');
}

function generateAttackGraph(inc) {
    const stages = inc.timeline.map(e => e.eventType);
    const uniqueStages = [...new Set(stages)];
    let html = '<div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap; padding:8px; background:var(--dark); border-radius:8px; margin:12px 0;">';
    uniqueStages.forEach((stage, idx) => {
        html += `<span style="background:var(--surface-light); padding:4px 12px; border-radius:12px;">${stage}</span>`;
        if (idx < uniqueStages.length-1) html += `<span style="color:var(--text-muted);">→</span>`;
    });
    html += '</div>';
    return html;
}

function renderIncidentsTable() {
    const tbody = document.getElementById('incidents-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No incidents generated yet.</td></tr>';
        updateIncidentStats();
        return;
    }
    const sorted = [...incidents].sort((a, b) => b.createdAt - a.createdAt);
    sorted.forEach(inc => {
        const row = document.createElement('tr');
        const severityClass = inc.severity || 'medium';
        const statusClass = inc.status === 'open' ? 'status-open' :
                            inc.status === 'investigating' ? 'status-investigating' :
                            inc.status === 'resolved' ? 'status-resolved' : 'status-fp';
        const stageStr = [...inc.attackStages].join(', ') || '—';
        const hostStr = [...inc.hosts].join(', ');
        const alertCount = inc.alertIds.size;
        const created = new Date(inc.createdAt).toLocaleString();
        row.innerHTML = `
            <td><strong>#${inc.id}</strong> ${inc.title}</td>
            <td><span class="severity-${severityClass}">${severityClass.toUpperCase()}</span></td>
            <td><span class="status-badge ${statusClass}">${inc.status.toUpperCase()}</span></td>
            <td>${hostStr}</td>
            <td>${alertCount}</td>
            <td>${inc.confidence}%</td>
            <td>${stageStr}</td>
            <td>${created}</td>
            <td>
                <button class="btn-action view-incident" data-id="${inc.id}">View</button>
                <button class="btn-action resolve-incident" data-id="${inc.id}" style="background:#10b981;color:white;">Resolve</button>
                <button class="btn-action fp-incident" data-id="${inc.id}" style="background:#6b7280;color:white;">FP</button>
            </td>
        `;
        tbody.appendChild(row);
    });
    updateIncidentStats();

    
    tbody.querySelectorAll('.view-incident').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            openIncidentDetail(id);
        });
    });
    tbody.querySelectorAll('.resolve-incident').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            resolveIncident(id);
        });
    });
    tbody.querySelectorAll('.fp-incident').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = parseInt(this.dataset.id);
            markIncidentFalsePositive(id);
        });
    });
}

function updateIncidentStats() {
    const open = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
    document.getElementById('incidents-open-count').textContent = open;
}

function generateIncidentSummary(inc) {
    const stages = [...inc.attackStages];
    const hostList = [...inc.hosts].join(', ');
    let summary = `This incident likely represents `;
    if (stages.includes('Exfiltration')) {
        summary += `a successful compromise of ${hostList}. `;
    } else if (stages.includes('Command & Control')) {
        summary += `an active command-and-control session from ${hostList}. `;
    } else if (stages.includes('Initial Access')) {
        summary += `an attempted initial access on ${hostList}. `;
    } else {
        summary += `suspicious activity involving ${hostList}. `;
    }
    
    if (stages.length > 1) {
        summary += `The attack progressed through ${stages.join(' → ')}. `;
    }
    
    summary += `Overall confidence: ${inc.confidence}%. `;
    
    const likelihood = inc.confidence > 80 ? 'High' : inc.confidence > 50 ? 'Medium' : 'Low';
    summary += `Likelihood of compromise: ${likelihood}.`;
    return summary;
}

function computeCorrelationReason(alerts) {
    const reasons = [];
    const hosts = new Set(alerts.flatMap(a => [a.src, a.dst]).filter(Boolean));
    if (hosts.size === 1) reasons.push('Same source/destination host');
    else if (hosts.size > 1) reasons.push('Shared hosts');

    const times = alerts.map(a => a.eventTimestamp).sort((a,b) => a-b);
    const windowMs = times[times.length-1] - times[0];
    if (windowMs < 30*60*1000) reasons.push(`Within ${Math.round(windowMs/60000)} minutes`);

    const mitres = new Set(alerts.map(a => a.mitre).filter(Boolean));
    if (mitres.size > 1) reasons.push(`Shared MITRE techniques: ${[...mitres].join(', ')}`);

    const stages = new Set(alerts.map(a => STAGE_MAP[a.eventType]).filter(Boolean));
    if (stages.size > 1) reasons.push(`Continuous attack progression: ${[...stages].join(' → ')}`);

    const iocs = new Set();
    alerts.forEach(a => {
        if (a.evidence?.iocType) iocs.add(a.evidence.iocValue);
    });
    if (iocs.size > 0) reasons.push(`Same IOC observed: ${[...iocs].join(', ')}`);

    return reasons.join('; ');
}

function computeCorrelationScore(alert1, alert2) {
    let score = 0;
    if (alert1.src === alert2.src) score += 35;
    if (alert1.dst === alert2.dst) score += 15;
    if (alert1.evidence?.iocValue && alert1.evidence.iocValue === alert2.evidence?.iocValue) score += 20;
    const tactic1 = MITRE_TECHNIQUES[alert1.mitre]?.tactic;
    const tactic2 = MITRE_TECHNIQUES[alert2.mitre]?.tactic;
    if (tactic1 && tactic1 === tactic2) score += 10;
    const timeDiff = Math.abs((alert1.eventTimestamp||0) - (alert2.eventTimestamp||0));
    if (timeDiff < 30*60*1000) score += 10;
    const stage1 = STAGE_MAP[alert1.eventType];
    const stage2 = STAGE_MAP[alert2.eventType];
    if (stage1 && stage1 === stage2) score += 10;
    return Math.min(score, 100);
}

function openIncidentDetail(incidentId) {
    const inc = incidents.find(i => i.id === incidentId);
    if (!inc) return;
    const modal = document.getElementById('incident-detail-modal');
    const title = document.getElementById('incident-detail-title');
    const content = document.getElementById('incident-detail-content');
    title.textContent = `Incident #${inc.id}: ${inc.title}`;

    let html = '';

    
    html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; margin-bottom: 16px; border-left: 4px solid var(--primary);">`;
    html += `<h4 style="margin:0 0 8px 0;"><i class="fas fa-brain"></i> AI Incident Summary</h4>`;
    html += `<p style="margin:0; font-size:14px; line-height:1.5;">${generateIncidentSummary(inc)}</p>`;
    html += `</div>`;

    
    if (inc.correlationReason) {
        html += `<div style="background: var(--surface-light); border-radius: 8px; padding: 12px; margin-bottom: 16px; border-left: 3px solid var(--warning);">`;
        html += `<strong><i class="fas fa-link"></i> Correlation Reason</strong><br>`;
        html += `<span style="font-size:13px; color:var(--text-muted);">${inc.correlationReason}</span>`;
        html += `</div>`;
    }

    
    html += `<div style="background: var(--surface-light); border-radius: 12px; padding: 16px; margin-bottom: 16px; border-left: 4px solid ${inc.confidence >= 80 ? 'var(--secondary)' : inc.confidence >= 50 ? 'var(--warning)' : 'var(--danger)'};">`;
    html += `<h4 style="margin:0 0 8px 0;">Incident Confidence: ${inc.confidence}%</h4>`;
    if (inc.confidenceBreakdown && inc.confidenceBreakdown.length) {
        html += `<div style="font-size:13px;">`;
        inc.confidenceBreakdown.forEach(item => {
            html += `<div style="display:flex; justify-content:space-between; padding:2px 0; border-bottom:1px solid var(--border);">`;
            html += `<span>${item.reason}</span>`;
            html += `<span style="font-weight:600; color:var(--primary);">+${item.contribution}%</span>`;
            html += `</div>`;
        });
        html += `</div>`;
    }
    html += `</div>`;

    
    let assetsHtml = '<h4 style="margin:12px 0 8px 0;"><i class="fas fa-server"></i> Affected Assets</h4><div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">';
    inc.hosts.forEach(host => {
        const asset = getAssetByIdentifier(host);
        if (asset) {
            assetsHtml += `
                <div style="background:var(--surface-light); padding:8px; border-radius:8px; border:1px solid var(--border);">
                    <strong>${asset.hostname}</strong><br>
                    IP: ${asset.ip}<br>
                    Criticality: ${asset.criticality}<br>
                    Owner: ${asset.owner}<br>
                    Status: ${asset.status}
                </div>
            `;
        } else {
            assetsHtml += `<div style="background:var(--surface-light); padding:8px; border-radius:8px; border:1px solid var(--border);">${host}</div>`;
        }
    });
    assetsHtml += '</div>';
    html += assetsHtml;

    
    const sources = [...new Set(inc.timeline.map(e => e.source || 'heuristic'))];
    let sourcesHtml = '<h4 style="margin:16px 0 8px 0;"><i class="fas fa-microscope"></i> Detection Sources</h4><div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;">';
    sources.forEach(s => {
        const icon = s === 'IOC' ? '🛡️' : s === 'ML' ? '🧠' : s === 'Rule' ? '⚖️' : s === 'Signature' ? '✍️' : '🔍';
        sourcesHtml += `<span style="background:var(--surface-light); padding:4px 12px; border-radius:12px; border:1px solid var(--border);">${icon} ${s}</span>`;
    });
    sourcesHtml += '</div>';
    html += sourcesHtml;

    
    html += `<h4 style="margin:12px 0 8px 0;"><i class="fas fa-sitemap"></i> Attack Progression</h4>`;
    html += generateAttackGraph(inc);

    
    
    const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
    const sortedTimeline = [...inc.timeline].sort(
        (a, b) => (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99)
    );
    const topAlertId = sortedTimeline[0]?.alertId;
    const topAlert = topAlertId ? timelineEvents.find(e => e.id === topAlertId) : null;
    if (topAlert) {
        const prediction = predictNextAttackStage(topAlert);
        html += `<div style="background:var(--surface-light); padding:12px; border-radius:8px; margin:12px 0; border-left:3px solid var(--warning);">`;
        html += `<strong><i class="fas fa-crosshairs"></i> Next Predicted Behaviour</strong><br>`;
        html += `<span style="font-size:18px; font-weight:700; color:var(--warning);">${prediction.nextPhase}</span>`;
        html += ` <span style="font-size:14px; color:var(--text-muted);">(${prediction.probability}% probability)</span>`;
        html += `<div style="font-size:13px; color:var(--text-muted); margin-top:4px;">${prediction.reasoning.join(' ')}</div>`;
        html += `</div>`;
    }

    
    if (topAlert) {
        const playbook = generateRecommendedActions(topAlert);
        if (playbook.actions.length) {
            html += `<h4 style="margin:16px 0 8px 0;"><i class="fas fa-tasks"></i> Recommended Response Playbook</h4>`;
            html += `<ul style="margin:0; padding-left:20px;">`;
            playbook.actions.forEach(action => {
                html += `<li style="padding:4px 0; font-size:14px;">${action}</li>`;
            });
            html += `</ul>`;
        }
    }

    
    html += `<h4 style="margin:16px 0 8px 0;"><i class="fas fa-clock"></i> Incident Timeline</h4>`;
    html += `<div style="max-height:200px; overflow-y:auto; border:1px solid var(--border); border-radius:8px; padding:8px; margin-bottom:16px;">`;
    inc.timeline.forEach(event => {
        html += `<div style="padding:4px 0; border-bottom:1px solid var(--border);">
            <span style="color:var(--text-muted);">${new Date(event.timestamp).toLocaleTimeString()}</span>
            <span class="severity-${event.severity}">${event.severity.toUpperCase()}</span>
            <strong>${event.eventType}</strong> – ${event.details}
        </div>`;
    });
    html += `</div>`;

    
    html += `<h4><i class="fas fa-bell"></i> Linked Alerts</h4><ul style="list-style:none; padding:0;">`;
    const alertIds = [...inc.alertIds];
    alertIds.forEach(id => {
        const alert = timelineEvents.find(e => e.id === id);
        if (alert) {
            html += `<li style="padding:4px 0; cursor:pointer;" onclick="openAlertInvestigation('${id}')">
                <span class="severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
                ${alert.eventType} (${formatAlertTime(alert)})
            </li>`;
        }
    });
    html += `</ul>`;

    
    html += `
        <div style="margin-top:16px; display:flex; gap:12px; flex-wrap:wrap;">
            <button class="btn-secondary" onclick="convertIncidentToCase(${inc.id})"><i class="fas fa-folder"></i> Convert to Case</button>
            <button class="btn-secondary" onclick="document.getElementById('hunting-query-input').value='${[...inc.hosts].map(h => `src:${h} OR dst:${h}`).join(' OR ')}'; switchView('hunting'); document.getElementById('hunting-run-btn').click();">🔍 Hunt Hosts</button>
            <button class="btn-secondary" onclick="switchView('investigation');">🌐 Investigation Graph</button>
            <button class="btn-secondary" onclick="resolveIncident(${inc.id})">✅ Resolve</button>
            <button class="btn-secondary" onclick="markIncidentFalsePositive(${inc.id})">❌ False Positive</button>
        </div>
    `;

    content.innerHTML = html;
    modal.classList.remove('hidden');
}


document.getElementById('close-incident-detail')?.addEventListener('click', () => {
    document.getElementById('incident-detail-modal').classList.add('hidden');
});
document.getElementById('incident-detail-modal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
});

function resolveIncident(id) {
    const inc = incidents.find(i => i.id === id);
    if (!inc) return;
    showConfirmModal('Resolve Incident', `Resolve incident #${id}?`, () => {
        inc.status = 'resolved';
        inc.resolvedAt = Date.now();
        inc.updatedAt = Date.now();
        
        inc.alertIds.forEach(alertId => {
            const alert = timelineEvents.find(e => e.id === alertId);
            if (alert && (alert.status === 'open' || alert.status === 'investigating')) {
                alert.status = 'resolved';
                alert.resolvedAt = Date.now();
            }
        });
        saveIncidents();
        renderIncidentsTable();
        showToast(`Incident #${id} resolved.`, 'success');
    });
}

function markIncidentFalsePositive(id) {
    const inc = incidents.find(i => i.id === id);
    if (!inc) return;
    showConfirmModal('False Positive', `Mark incident #${id} as false positive?`, () => {
        inc.status = 'false_positive';
        inc.updatedAt = Date.now();
        
        inc.alertIds.forEach(alertId => {
            const alert = timelineEvents.find(e => e.id === alertId);
            if (alert && (alert.status === 'open' || alert.status === 'investigating')) {
                alert.status = 'false_positive';
                alert.falsePositiveReason = 'Incident marked FP';
            }
        });
        saveIncidents();
        renderIncidentsTable();
        showToast(`Incident #${id} marked as false positive.`, 'info');
    });
}

function convertIncidentToCase(incidentId) {
    const inc = incidents.find(i => i.id === incidentId);
    if (!inc) return;
    
    const caseData = {
        title: inc.title,
        severity: inc.severity,
        status: inc.status === 'resolved' ? 'resolved' : 'open',
        assignedTo: inc.assignedTo || null,
        description: `Auto-generated from incident #${inc.id}\nHosts: ${[...inc.hosts].join(', ')}\nStages: ${[...inc.attackStages].join(' → ')}`,
        alerts: [...inc.alertIds],
        evidence: [...inc.alertIds].map(id => ({ type: 'alert', id })),
        priority: inc.severity === 'critical' ? 'P1' : inc.severity === 'high' ? 'P2' : 'P3',
    };
    const newCase = createCase(caseData);
    showToast(`Case #${newCase.id} created from incident #${incidentId}.`, 'success');
    switchView('cases');
}

document.getElementById('run-correlation-btn')?.addEventListener('click', function() {
    correlateAlerts();
    showToast('Correlation run manually.', 'success');
});

if (window.threatInterval) clearInterval(window.threatInterval);
window.threatInterval = setInterval(runThreatDetection, 10000);

fetchPackets = function() {
    originalFetchPackets();
    setTimeout(runThreatDetection, 500); 
};

if (window.hostRiskInterval) clearInterval(window.hostRiskInterval);
window.hostRiskInterval = setInterval(() => {
  refreshHostRisk();
  updateFlowAnalysisTable();
  updateHostRiskChart();
  updateHostRiskHeatmap();
}, 2000);

if (window.geoInterval) clearInterval(window.geoInterval);

window.geoInterval = setInterval(() => {
  if (geoViewVisible) {
    updateGeoStats();
  }
}, 15000);

console.log("✅ Auto-refresh enabled for host risk, flow analysis, and charts");






const URGENCY = {
    IMMEDIATE: { level: 'immediate', label: 'Immediate', icon: '🟥', order: 0 },
    NEXT: { level: 'next', label: 'Next', icon: '🟧', order: 1 },
    FOLLOWUP: { level: 'followup', label: 'Follow-up', icon: '🟨', order: 2 },
    LONGTERM: { level: 'longterm', label: 'Long-term', icon: '🟩', order: 3 }
};


const ACTION_TEMPLATES = {
    isolate_host: {
        label: 'Isolate Host',
        icon: '🔒',
        urgency: URGENCY.IMMEDIATE,
        time: '2 minutes',
        impact: 'High',
        automation: true,
        defaultReason: 'Host is exhibiting malicious behaviour and poses an immediate threat.'
    },
    block_ip: {
        label: 'Block IP',
        icon: '🚫',
        urgency: URGENCY.IMMEDIATE,
        time: '1 minute',
        impact: 'High',
        automation: true,
        defaultReason: 'Malicious traffic detected from this IP address.'
    },
    capture_memory: {
        label: 'Capture Memory',
        icon: '💾',
        urgency: URGENCY.NEXT,
        time: '15 minutes',
        impact: 'Medium',
        automation: false,
        defaultReason: 'Possible malware execution detected. Memory may contain payloads that will not persist after reboot.'
    },
    capture_pcap: {
        label: 'Capture PCAP',
        icon: '📦',
        urgency: URGENCY.NEXT,
        time: '10 minutes',
        impact: 'Medium',
        automation: false,
        defaultReason: 'Active network communications may contain commands and exfiltration data.'
    },
    check_ad_logs: {
        label: 'Review AD Logs',
        icon: '📋',
        urgency: URGENCY.FOLLOWUP,
        time: '20 minutes',
        impact: 'Medium',
        automation: false,
        defaultReason: 'Authentication logs may reveal compromised accounts and lateral movement.'
    },
    hunt_lateral: {
        label: 'Hunt Lateral Movement',
        icon: '🔍',
        urgency: URGENCY.FOLLOWUP,
        time: '30 minutes',
        impact: 'High',
        automation: false,
        defaultReason: 'The attacker may have moved to other hosts using compromised credentials.'
    },
    update_firewall: {
        label: 'Update Firewall',
        icon: '🛡️',
        urgency: URGENCY.FOLLOWUP,
        time: '5 minutes',
        impact: 'Medium',
        automation: true,
        defaultReason: 'Block malicious destinations at the perimeter to prevent further communication.'
    },
    quarantine_host: {
        label: 'Quarantine Host',
        icon: '🧊',
        urgency: URGENCY.IMMEDIATE,
        time: '3 minutes',
        impact: 'High',
        automation: true,
        defaultReason: 'Host is confirmed compromised and must be isolated from the network.'
    },
    forensic_analysis: {
        label: 'Forensic Analysis',
        icon: '🔬',
        urgency: URGENCY.FOLLOWUP,
        time: '2 hours',
        impact: 'Medium',
        automation: false,
        defaultReason: 'Deep-dive analysis required to understand the full scope of compromise.'
    },
    add_ioc: {
        label: 'Add IOC',
        icon: '⚠️',
        urgency: URGENCY.FOLLOWUP,
        time: '2 minutes',
        impact: 'Low',
        automation: true,
        defaultReason: 'Indicator of Compromise should be added to threat intelligence feeds.'
    },
    create_case: {
        label: 'Create Case',
        icon: '📁',
        urgency: URGENCY.FOLLOWUP,
        time: '5 minutes',
        impact: 'Low',
        automation: true,
        defaultReason: 'Formal case tracking is required for this incident.'
    },
    notify_team: {
        label: 'Notify Team',
        icon: '📢',
        urgency: URGENCY.IMMEDIATE,
        time: '2 minutes',
        impact: 'Medium',
        automation: true,
        defaultReason: 'Security team must be alerted to the active incident.'
    },
    review_logs: {
        label: 'Review Logs',
        icon: '👀',
        urgency: URGENCY.FOLLOWUP,
        time: '15 minutes',
        impact: 'Low',
        automation: false,
        defaultReason: 'Comprehensive log review is needed to identify the attack timeline.'
    },
    enhance_monitoring: {
        label: 'Enhance Monitoring',
        icon: '📊',
        urgency: URGENCY.LONGTERM,
        time: '1 hour',
        impact: 'Low',
        automation: true,
        defaultReason: 'Additional monitoring rules should be applied for early detection.'
    },
    reset_credentials: {
        label: 'Reset Credentials',
        icon: '🔑',
        urgency: URGENCY.NEXT,
        time: '10 minutes',
        impact: 'High',
        automation: false,
        defaultReason: 'Compromised credentials must be rotated immediately.'
    }
};


function generateEnhancedCaseRecommendations(caseId) {
    const caseObj = cases.find(c => c.id === caseId);
    if (!caseObj) {
        return {
            summary: 'Case not found.',
            confidence: 0,
            evidence: [],
            primaryObjective: 'Unable to generate recommendations.',
            actions: [],
            businessImpact: 'Unknown',
            likelyObjective: 'Unknown'
        };
    }

    const alertIds = caseObj.alerts || [];
    if (alertIds.length === 0) {
        return {
            summary: 'No alerts linked to this case.',
            confidence: 0,
            evidence: [],
            primaryObjective: 'No alerts to analyze.',
            actions: [],
            businessImpact: 'Unknown',
            likelyObjective: 'Unknown'
        };
    }

    
    const alerts = alertIds
        .map(id => timelineEvents.find(e => e.id === id))
        .filter(Boolean);

    if (alerts.length === 0) {
        return {
            summary: 'No valid alerts found.',
            confidence: 0,
            evidence: [],
            primaryObjective: 'No valid alerts to analyze.',
            actions: [],
            businessImpact: 'Unknown',
            likelyObjective: 'Unknown'
        };
    }

    
    const evidence = [];
    const hostSet = new Set();
    let maxSeverity = 'low';
    let totalConfidence = 0;
    let hasIOC = false;
    let hasBeaconing = false;
    let hasExfil = false;
    let hasBruteForce = false;
    let hasPortScan = false;
    let hasC2 = false;
    let hasLateral = false;
    let hasMalware = false;
    let hasCredentialAccess = false;
    let hasRecon = false;
    let hasGeo = false;
    let hasTor = false;
    let hasMultiStage = false;
    let hasHostRiskChange = false;
    let assetCriticality = 'Medium';
    let affectedHosts = [];
    let detectionSources = new Set();

    const severityWeights = { low: 1, medium: 2, high: 3, critical: 4 };

    for (const alert of alerts) {
        const sev = alert.severity || 'low';
        if (severityWeights[sev] > severityWeights[maxSeverity]) maxSeverity = sev;
        totalConfidence += (alert.confidence || 50);
        if (alert.src) {
            hostSet.add(alert.src);
            const asset = getAssetByIdentifier(alert.src);
            if (asset) {
                affectedHosts.push(asset.hostname || alert.src);
                if (asset.criticality && severityWeights[asset.criticality.toLowerCase()] > severityWeights[assetCriticality.toLowerCase()]) {
                    assetCriticality = asset.criticality;
                }
            } else {
                affectedHosts.push(alert.src);
            }
        }
        if (alert.dst) hostSet.add(alert.dst);
        if (alert.source) detectionSources.add(alert.source);

        
        const type = alert.eventType || '';
        if (type.includes('IOC')) { hasIOC = true; evidence.push('IOC Match'); }
        if (type.includes('Beaconing')) { hasBeaconing = true; evidence.push('Active Beaconing'); }
        if (type.includes('Exfiltration')) { hasExfil = true; evidence.push('Data Exfiltration'); }
        if (type.includes('Brute Force')) { hasBruteForce = true; evidence.push('Brute Force Attempts'); }
        if (type.includes('Port Scan')) { hasPortScan = true; evidence.push('Port Scanning'); }
        if (type.includes('C2')) { hasC2 = true; evidence.push('C2 Communication'); }
        if (type.includes('Lateral')) { hasLateral = true; evidence.push('Lateral Movement'); }
        if (type.includes('Malware')) { hasMalware = true; evidence.push('Malware Detection'); }
        if (type.includes('Credential')) { hasCredentialAccess = true; evidence.push('Credential Access'); }
        if (type.includes('Recon')) { hasRecon = true; evidence.push('Reconnaissance'); }
        if (type.includes('Geo')) { hasGeo = true; evidence.push('Suspicious Geolocation'); }
        if (type.includes('Tor')) { hasTor = true; evidence.push('Tor Connection'); }
        if (type.includes('Multi-Stage')) { hasMultiStage = true; evidence.push('Multi-Stage Attack'); }
        if (type.includes('Host Risk Change')) { hasHostRiskChange = true; evidence.push('Host Risk Escalation'); }

        
        if (alert.src && uebaData[alert.src]?.score >= 50) {
            evidence.push('High UEBA Anomaly');
        }
        if (alert.dst && uebaData[alert.dst]?.score >= 50) {
            evidence.push('High UEBA Anomaly (Destination)');
        }
    }

    
    const avgConf = alerts.length > 0 ? totalConfidence / alerts.length : 0;
    let confidence = avgConf;
    
    const evidenceCount = evidence.length;
    if (evidenceCount >= 5) confidence += 15;
    else if (evidenceCount >= 3) confidence += 10;
    else if (evidenceCount >= 2) confidence += 5;
    
    if (maxSeverity === 'critical') confidence += 10;
    else if (maxSeverity === 'high') confidence += 5;
    
    if (assetCriticality === 'Critical') confidence += 8;
    else if (assetCriticality === 'High') confidence += 4;
    confidence = Math.min(100, Math.round(confidence));

    
    let businessImpact = 'Low';
    if (maxSeverity === 'critical' || hasExfil || hasC2 || hasLateral) businessImpact = 'High';
    else if (maxSeverity === 'high' || hasMalware || hasCredentialAccess) businessImpact = 'Medium';

    
    let likelyObjective = 'Unknown';
    if (hasExfil && hasC2) likelyObjective = 'Data exfiltration via C2 channel.';
    else if (hasExfil) likelyObjective = 'Data exfiltration.';
    else if (hasC2 && hasBeaconing) likelyObjective = 'Command & Control with beaconing.';
    else if (hasC2) likelyObjective = 'Command & Control activity.';
    else if (hasLateral && hasCredentialAccess) likelyObjective = 'Lateral movement using stolen credentials.';
    else if (hasLateral) likelyObjective = 'Lateral movement.';
    else if (hasBruteForce && hasCredentialAccess) likelyObjective = 'Credential compromise via brute force.';
    else if (hasBruteForce) likelyObjective = 'Brute force attack.';
    else if (hasRecon && hasPortScan) likelyObjective = 'Reconnaissance for targeted attack.';
    else if (hasMultiStage) likelyObjective = 'Multi-stage attack chain in progress.';
    else if (hasMalware) likelyObjective = 'Malware infection.';
    else if (hasGeo && hasC2) likelyObjective = 'Geopolitical threat actor activity.';
    else if (hasTor) likelyObjective = 'Anonymisation activity (Tor).';
    else if (hasHostRiskChange) likelyObjective = 'Host compromise progression.';
    else if (alerts.length > 1) likelyObjective = 'Multiple suspicious activities detected.';

    
    let primaryObjective = 'Investigate and contain the affected host(s).';
    if (hasExfil || hasC2) primaryObjective = 'Contain the host immediately to prevent data loss.';
    else if (hasLateral) primaryObjective = 'Stop lateral movement and isolate affected hosts.';
    else if (hasBruteForce) primaryObjective = 'Block attacking IPs and secure exposed services.';
    else if (hasMalware) primaryObjective = 'Identify and remove malware from affected systems.';
    else if (hasMultiStage) primaryObjective = 'Break the attack chain and contain all affected hosts.';

    
    const actionSet = new Map();
    const sourceHost = affectedHosts.length > 0 ? affectedHosts[0] : 'unknown';

    
    const actionDecisions = [];

    
    if (hasExfil || hasC2 || hasMultiStage) {
        actionDecisions.push({ key: 'isolate_host', urgency: URGENCY.IMMEDIATE, reason: 'Host is actively compromised and poses an immediate threat to the network.' });
    }
    if (hasIOC || hasC2 || hasBeaconing) {
        actionDecisions.push({ key: 'block_ip', urgency: URGENCY.IMMEDIATE, reason: 'Malicious IP communication detected – block at the firewall.' });
    }
    if (hasBruteForce || hasCredentialAccess) {
        actionDecisions.push({ key: 'reset_credentials', urgency: URGENCY.NEXT, reason: 'Credentials may have been compromised – rotate immediately.' });
    }
    if (hasMalware || hasC2 || hasMultiStage) {
        actionDecisions.push({ key: 'capture_memory', urgency: URGENCY.NEXT, reason: 'Malware execution is suspected. Memory may contain critical forensic evidence.' });
    }
    if (hasC2 || hasBeaconing || hasExfil) {
        actionDecisions.push({ key: 'capture_pcap', urgency: URGENCY.NEXT, reason: 'Active network traffic may reveal commands and data exfiltration.' });
    }
    if (hasLateral || hasCredentialAccess) {
        actionDecisions.push({ key: 'check_ad_logs', urgency: URGENCY.FOLLOWUP, reason: 'Authentication logs are critical for identifying compromised accounts.' });
    }
    if (hasLateral || hasMultiStage) {
        actionDecisions.push({ key: 'hunt_lateral', urgency: URGENCY.FOLLOWUP, reason: 'The attacker may have moved to other hosts – hunt across the environment.' });
    }
    if (hasC2 || hasExfil) {
        actionDecisions.push({ key: 'update_firewall', urgency: URGENCY.FOLLOWUP, reason: 'Block malicious destinations at the perimeter to prevent further communication.' });
    }
    if (hasMalware || hasMultiStage) {
        actionDecisions.push({ key: 'forensic_analysis', urgency: URGENCY.FOLLOWUP, reason: 'Deep-dive analysis required to understand full scope and impact.' });
    }
    if (hasIOC) {
        actionDecisions.push({ key: 'add_ioc', urgency: URGENCY.FOLLOWUP, reason: 'Add indicators to threat intelligence feeds for broader protection.' });
    }
    if (hasExfil || hasC2 || hasMultiStage) {
        actionDecisions.push({ key: 'notify_team', urgency: URGENCY.IMMEDIATE, reason: 'The security team must be alerted to this active incident.' });
    }
    if (hasRecon || hasPortScan) {
        actionDecisions.push({ key: 'review_logs', urgency: URGENCY.FOLLOWUP, reason: 'Review logs to identify the full reconnaissance pattern.' });
    }
    if (hasGeo || hasTor) {
        actionDecisions.push({ key: 'enhance_monitoring', urgency: URGENCY.LONGTERM, reason: 'Monitor for further communications with suspicious regions.' });
    }

    
    const existingKeys = new Set(actionDecisions.map(d => d.key));
    if (!existingKeys.has('isolate_host') && (affectedHosts.length > 0)) {
        actionDecisions.push({ key: 'isolate_host', urgency: URGENCY.IMMEDIATE, reason: 'Host is potentially compromised – isolate as a precaution.' });
    }
    if (!existingKeys.has('notify_team')) {
        actionDecisions.push({ key: 'notify_team', urgency: URGENCY.IMMEDIATE, reason: 'Alert the security team to the investigation.' });
    }
    if (!existingKeys.has('review_logs')) {
        actionDecisions.push({ key: 'review_logs', urgency: URGENCY.FOLLOWUP, reason: 'Comprehensive log review is recommended.' });
    }
    if (!existingKeys.has('enhance_monitoring') && alerts.length > 0) {
        actionDecisions.push({ key: 'enhance_monitoring', urgency: URGENCY.LONGTERM, reason: 'Enhance monitoring for similar activity.' });
    }

    
    const seen = new Set();
    const uniqueActions = [];
    for (const d of actionDecisions) {
        if (!seen.has(d.key)) {
            seen.add(d.key);
            uniqueActions.push(d);
        }
    }

    
    const actions = uniqueActions.map(d => {
        const template = ACTION_TEMPLATES[d.key] || {
            label: d.key.replace(/_/g, ' ').toUpperCase(),
            icon: '●',
            urgency: URGENCY.FOLLOWUP,
            time: 'Unknown',
            impact: 'Medium',
            automation: false,
            defaultReason: d.reason || 'Recommended action.'
        };
        
        const reason = d.reason || template.defaultReason;
        
        let actionText = template.label;
        if (template.label === 'Isolate Host') actionText = `Isolate ${sourceHost} from the network`;
        else if (template.label === 'Block IP') actionText = `Block malicious IP addresses`;
        else if (template.label === 'Reset Credentials') actionText = `Reset credentials for affected accounts`;
        else if (template.label === 'Capture Memory') actionText = `Capture memory from ${sourceHost}`;
        else if (template.label === 'Capture PCAP') actionText = `Capture PCAP for ${sourceHost}`;
        else if (template.label === 'Review AD Logs') actionText = `Check Active Directory logs`;
        else if (template.label === 'Hunt Lateral Movement') actionText = `Hunt for lateral movement from ${sourceHost}`;
        else if (template.label === 'Update Firewall') actionText = `Update firewall rules`;
        else if (template.label === 'Forensic Analysis') actionText = `Perform forensic analysis on ${sourceHost}`;
        else if (template.label === 'Add IOC') actionText = `Add IOCs to threat feeds`;
        else if (template.label === 'Notify Team') actionText = `Notify security team`;
        else if (template.label === 'Review Logs') actionText = `Review logs`;
        else if (template.label === 'Enhance Monitoring') actionText = `Enhance monitoring`;
        else if (template.label === 'Quarantine Host') actionText = `Quarantine ${sourceHost}`;

        return {
            id: d.key,
            label: template.label,
            icon: template.icon,
            urgency: template.urgency,
            reason: reason,
            time: template.time,
            impact: template.impact,
            automation: template.automation,
            actionText: actionText,
            
            action: actionText
        };
    });

    
    actions.sort((a, b) => a.urgency.order - b.urgency.order);

    
    const hostList = affectedHosts.length > 1 ? `${affectedHosts.length} hosts` : affectedHosts[0] || 'Unknown host';
    let summary = '';
    if (maxSeverity === 'critical' || confidence >= 85) {
        summary = `${hostList} is highly likely to be compromised.`;
    } else if (maxSeverity === 'high' || confidence >= 65) {
        summary = `${hostList} shows suspicious behaviour consistent with compromise.`;
    } else if (confidence >= 40) {
        summary = `${hostList} exhibits unusual activity requiring investigation.`;
    } else {
        summary = `${hostList} has triggered alerts that warrant review.`;
    }

    
    if (hasExfil) summary += ' Data exfiltration is suspected.';
    if (hasC2) summary += ' C2 communication is active.';
    if (hasLateral) summary += ' Lateral movement may be in progress.';
    if (hasMalware) summary += ' Malware infection is suspected.';
    if (hasBruteForce) summary += ' Brute force attempts were observed.';
    if (hasIOC) summary += ' Known indicators were matched.';

    
    const playbook = {
        summary: summary,
        confidence: confidence,
        evidence: evidence,
        primaryObjective: primaryObjective,
        actions: actions,
        businessImpact: businessImpact,
        likelyObjective: likelyObjective,
        maxSeverity: maxSeverity,
        affectedHosts: affectedHosts,
        alertCount: alerts.length,
        avgConfidence: Math.round(avgConf),
        detectionSources: Array.from(detectionSources)
    };

    return playbook;
}


function renderEnhancedCaseRecommendations(caseId) {
    const container = document.getElementById('case-recommendations-list');
    const confidenceBadge = document.getElementById('rec-confidence-score');
    if (!container) return;

    const playbook = generateEnhancedCaseRecommendations(caseId);

    
    if (confidenceBadge) {
        confidenceBadge.textContent = playbook.confidence;
        const badge = document.getElementById('rec-confidence-badge');
        if (badge) {
            const color = playbook.confidence >= 80 ? 'var(--secondary)' :
                          playbook.confidence >= 50 ? 'var(--warning)' :
                          'var(--danger)';
            badge.style.borderColor = color;
            badge.style.color = color;
        }
    }

    if (!playbook.actions || playbook.actions.length === 0) {
        container.innerHTML = `
            <div style="color: var(--text-muted); font-size: 14px; text-align: center; padding: 16px 0;">
                <i class="fas fa-info-circle"></i>
                ${playbook.summary || 'No recommendations available for this case.'}
            </div>
        `;
        return;
    }

    
    let html = '';

    
    html += `
        <div style="background: var(--dark); border-radius: 12px; padding: 16px; margin-bottom: 16px; border-left: 4px solid ${playbook.confidence >= 80 ? 'var(--secondary)' : playbook.confidence >= 50 ? 'var(--warning)' : 'var(--danger)'};">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <i class="fas fa-brain" style="color: var(--primary); font-size: 20px;"></i>
                <span style="font-weight: 700; font-size: 16px;">AI Incident Summary</span>
                <span style="margin-left: auto; font-size: 13px; color: var(--text-muted); background: var(--surface-light); padding: 2px 12px; border-radius: 12px;">
                    ${playbook.alertCount} alerts
                </span>
            </div>
            <p style="margin: 4px 0 12px 0; font-size: 15px; line-height: 1.6;">${playbook.summary}</p>
            <div style="display: flex; flex-wrap: wrap; gap: 12px; font-size: 13px; color: var(--text-muted);">
                <div><strong>Confidence:</strong> <span style="color: ${playbook.confidence >= 80 ? 'var(--secondary)' : playbook.confidence >= 50 ? 'var(--warning)' : 'var(--danger)'}; font-weight: 700;">${playbook.confidence}%</span></div>
                <div><strong>Business Impact:</strong> <span style="color: ${playbook.businessImpact === 'High' ? 'var(--danger)' : playbook.businessImpact === 'Medium' ? 'var(--warning)' : 'var(--secondary)'}; font-weight: 600;">${playbook.businessImpact}</span></div>
                <div><strong>Likely Objective:</strong> ${playbook.likelyObjective}</div>
                <div><strong>Hosts:</strong> ${playbook.affectedHosts.join(', ') || 'Unknown'}</div>
            </div>
        </div>
    `;

    
    if (playbook.evidence.length > 0) {
        html += `
            <div style="margin-bottom: 16px;">
                <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-list-check" style="color: var(--primary);"></i>
                    Supporting Evidence
                    <span style="font-size: 12px; color: var(--text-muted); font-weight: 400;">(${playbook.evidence.length} indicators)</span>
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                    ${playbook.evidence.map(e => `
                        <span style="background: rgba(99, 102, 241, 0.15); color: var(--primary); padding: 4px 12px; border-radius: 20px; font-size: 12px; border: 1px solid rgba(99, 102, 241, 0.2);">
                            ✅ ${e}
                        </span>
                    `).join('')}
                </div>
            </div>
        `;
    }

    
    html += `
        <div style="background: var(--surface); border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; border: 1px solid var(--border);">
            <div style="font-weight: 600; font-size: 13px; color: var(--text-muted); margin-bottom: 4px;">
                <i class="fas fa-bullseye" style="color: var(--primary);"></i> Primary Objective
            </div>
            <div style="font-size: 15px; font-weight: 500;">${playbook.primaryObjective}</div>
        </div>
    `;

    
    html += `
        <div style="font-weight: 600; font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <i class="fas fa-tasks" style="color: var(--warning);"></i>
            Recommended Response
        </div>
    `;

    
    const groups = {};
    for (const action of playbook.actions) {
        const key = action.urgency.level;
        if (!groups[key]) groups[key] = [];
        groups[key].push(action);
    }

    
    const order = ['immediate', 'next', 'followup', 'longterm'];
    for (const level of order) {
        const actionList = groups[level] || [];
        if (actionList.length === 0) continue;
        const urgency = actionList[0].urgency;
        html += `
            <div style="margin-bottom: 12px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                    <span style="font-size: 18px;">${urgency.icon}</span>
                    <span style="font-weight: 600; font-size: 14px; color: var(--text);">${urgency.label}</span>
                    <span style="font-size: 12px; color: var(--text-muted); font-weight: 400;">${actionList.length} action${actionList.length > 1 ? 's' : ''}</span>
                </div>
                <div style="display: flex; flex-direction: column; gap: 8px; padding-left: 8px;">
        `;

        for (const action of actionList) {
            const doneKey = `rec_done_${caseId}_${action.id}`;
            const isDone = localStorage.getItem(doneKey) === 'true';

            
            let automationBadge = '';
            if (action.automation) {
                automationBadge = `<span style="font-size: 11px; background: rgba(16, 185, 129, 0.15); color: var(--secondary); padding: 0 8px; border-radius: 10px;">🤖 Auto</span>`;
            } else {
                automationBadge = `<span style="font-size: 11px; background: rgba(245, 158, 11, 0.15); color: var(--warning); padding: 0 8px; border-radius: 10px;">👤 Manual</span>`;
            }

            
            let impactColor = 'var(--secondary)';
            if (action.impact === 'High') impactColor = 'var(--danger)';
            else if (action.impact === 'Medium') impactColor = 'var(--warning)';

            html += `
                <div class="rec-action-item" data-action-id="${action.id}" data-case-id="${caseId}"
                     style="display: flex; flex-direction: column; gap: 6px; padding: 12px 16px;
                            background: ${isDone ? 'rgba(16, 185, 129, 0.06)' : 'var(--dark)'};
                            border-radius: 8px; border: 1px solid ${isDone ? 'rgba(16, 185, 129, 0.3)' : 'var(--border)'};
                            cursor: pointer; transition: all 0.2s; user-select: none;"
                     onmouseover="this.style.borderColor='var(--primary)'"
                     onmouseout="this.style.borderColor='${isDone ? 'rgba(16, 185, 129, 0.3)' : 'var(--border)'}'">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 22px; width: 32px; text-align: center;">${action.icon}</span>
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-weight: 600; font-size: 15px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                                ${action.label}
                                ${isDone ? '<span style="font-size: 12px; color: var(--secondary);"><i class="fas fa-check-circle"></i> Done</span>' : ''}
                                ${automationBadge}
                            </div>
                            <div style="font-size: 13px; color: var(--text-muted); line-height: 1.4;">
                                ${action.actionText}
                            </div>
                        </div>
                        ${!isDone ? `<button class="rec-execute-btn btn-primary" style="padding: 4px 14px; font-size: 12px; border-radius: 6px; border: none; cursor: pointer; flex-shrink: 0;" data-action-id="${action.id}" data-case-id="${caseId}">Execute</button>` : ''}
                    </div>
                    <div style="display: flex; flex-wrap: wrap; gap: 12px; padding-left: 44px; font-size: 12px; color: var(--text-muted);">
                        <span><i class="fas fa-clock"></i> ${action.time}</span>
                        <span><i class="fas fa-gauge-high" style="color: ${impactColor};"></i> Impact: <span style="color: ${impactColor}; font-weight: 500;">${action.impact}</span></span>
                        <span style="flex: 1; min-width: 200px;"><i class="fas fa-lightbulb" style="color: var(--warning);"></i> ${action.reason}</span>
                    </div>
                </div>
            `;
        }

        html += `</div></div>`;
    }

    
    if (playbook.detectionSources && playbook.detectionSources.length) {
        html += `
            <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; flex-wrap: wrap; gap: 8px; font-size: 12px; color: var(--text-muted);">
                <span style="font-weight: 500;">Detection sources:</span>
                ${playbook.detectionSources.map(s => `<span style="background: var(--surface); padding: 2px 10px; border-radius: 12px;">${s}</span>`).join('')}
            </div>
        `;
    }

    container.innerHTML = html;

    
    container.querySelectorAll('.rec-action-item').forEach(item => {
        item.addEventListener('click', function(e) {
            if (e.target.closest('.rec-execute-btn')) return;
            const actionId = this.dataset.actionId;
            const caseId = this.dataset.caseId;
            const key = `rec_done_${caseId}_${actionId}`;
            const current = localStorage.getItem(key) === 'true';
            localStorage.setItem(key, current ? 'false' : 'true');
            renderEnhancedCaseRecommendations(parseInt(caseId));
        });
    });

    container.querySelectorAll('.rec-execute-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const actionId = this.dataset.actionId;
            const caseId = parseInt(this.dataset.caseId);
            const item = this.closest('.rec-action-item');
            let label = actionId;
            if (item) {
                const labelEl = item.querySelector('.rec-action-item > div > div > div:first-child');
                if (labelEl) label = labelEl.textContent.trim().replace(/Done$/, '').trim();
            }
            
            const playbook = generateEnhancedCaseRecommendations(caseId);
            const action = playbook.actions.find(a => a.id === actionId);
            const actionText = action ? action.actionText : label;
            executeEnhancedRecommendation(caseId, actionId, actionText);
        });
    });
}


function executeEnhancedRecommendation(caseId, actionId, label) {
    const caseObj = cases.find(c => c.id === caseId);
    const caseTitle = caseObj ? caseObj.title : `Case #${caseId}`;

    
    const actionMap = {
        'isolate_host': { verb: 'Isolating host', icon: '🔒' },
        'block_ip': { verb: 'Blocking IP', icon: '🚫' },
        'capture_memory': { verb: 'Initiating memory capture', icon: '💾' },
        'capture_pcap': { verb: 'Initiating PCAP capture', icon: '📦' },
        'check_ad_logs': { verb: 'Checking AD logs', icon: '📋' },
        'hunt_lateral': { verb: 'Hunting lateral movement', icon: '🔍' },
        'update_firewall': { verb: 'Updating firewall', icon: '🛡️' },
        'quarantine_host': { verb: 'Quarantining host', icon: '🧊' },
        'forensic_analysis': { verb: 'Starting forensic analysis', icon: '🔬' },
        'add_ioc': { verb: 'Adding IOC', icon: '⚠️' },
        'notify_team': { verb: 'Notifying team', icon: '📢' },
        'review_logs': { verb: 'Reviewing logs', icon: '👀' },
        'enhance_monitoring': { verb: 'Enhancing monitoring', icon: '📊' },
        'reset_credentials': { verb: 'Resetting credentials', icon: '🔑' }
    };

    const info = actionMap[actionId] || { verb: `Executing: ${label}`, icon: '●' };

    
    showToast(`${info.icon} ${info.verb} for ${caseTitle}`, 'success');

    
    addHighlightedActionLog(
        actionId,
        caseTitle,
        `AI-recommended action "${label}" executed for case #${caseId}`
    );

    
    const caseIdx = cases.findIndex(c => c.id === caseId);
    if (caseIdx !== -1) {
        const c = cases[caseIdx];
        if (!c.notes) c.notes = [];
        c.notes.push({
            timestamp: Date.now(),
            text: `🤖 AI action executed: ${label} (${info.verb})`
        });
        c.updatedAt = Date.now();
        saveCases();
        if (currentCaseDetailId === caseId) {
            openCaseDetail(caseId);
        }
    }

    
    const key = `rec_done_${caseId}_${actionId}`;
    localStorage.setItem(key, 'true');
    renderEnhancedCaseRecommendations(caseId);
}


const _origOpenCaseDetailEnhanced = window.openCaseDetail || function() {};

window.openCaseDetail = function(caseId) {
    if (typeof _origOpenCaseDetailEnhanced === 'function') {
        _origOpenCaseDetailEnhanced(caseId);
    }

    setTimeout(() => {
        renderEnhancedCaseRecommendations(caseId);
    }, 50);
};


const caseDetailModalEnhanced = document.getElementById('case-detail-modal');
if (caseDetailModalEnhanced) {
    const observerEnhanced = new MutationObserver(() => {
        if (!caseDetailModalEnhanced.classList.contains('hidden')) {
            const content = document.getElementById('case-detail-content');
            if (content) {
                const titleEl = document.getElementById('case-detail-title');
                if (titleEl) {
                    const match = titleEl.textContent.match(/#(\d+)/);
                    if (match) {
                        const caseId = parseInt(match[1]);
                        if (!isNaN(caseId)) {
                            setTimeout(() => renderEnhancedCaseRecommendations(caseId), 100);
                        }
                    }
                }
            }
        }
    });
    observerEnhanced.observe(caseDetailModalEnhanced, { attributes: true, attributeFilter: ['class'] });
}


document.addEventListener('click', function(e) {
    const btn = e.target.closest('#rec-refresh-btn');
    if (btn) {
        e.preventDefault();
        const titleEl = document.getElementById('case-detail-title');
        if (titleEl) {
            const match = titleEl.textContent.match(/#(\d+)/);
            if (match) {
                const caseId = parseInt(match[1]);
                if (!isNaN(caseId)) {
                    renderEnhancedCaseRecommendations(caseId);
                    showToast('Playbook refreshed.', 'success');
                }
            }
        }
    }
});


window.generateEnhancedCaseRecommendations = generateEnhancedCaseRecommendations;
window.renderEnhancedCaseRecommendations = renderEnhancedCaseRecommendations;
window.executeEnhancedRecommendation = executeEnhancedRecommendation;

console.log('✅ Enhanced AI Case Recommendations (Playbook) loaded.');






function generateIocIntelSummary(ioc) {
    if (!ioc || !ioc.hits || ioc.hits.length === 0) {
        return {
            summary: 'No hits recorded for this IOC.',
            hosts: [],
            behaviours: [],
            risk: 'Unknown',
            confidence: 0,
            firstSeen: null,
            lastSeen: null,
            isActive: false,
            campaignPhases: [],
            campaignProgress: 0,
            relatedIOCs: [],
            incidents: [],
            affectedHosts: []
        };
    }

    
    const totalHits = ioc.hits.length;
    const hostSet = new Set();
    const eventTypeSet = new Set();
    let maxSeverity = 'low';
    let severityWeights = { low: 1, medium: 2, high: 3, critical: 4 };
    let confidenceSum = 0;
    let confidenceCount = 0;
    let firstSeen = Infinity;
    let lastSeen = 0;

    
    for (const hit of ioc.hits) {
        if (hit.src) hostSet.add(hit.src);
        if (hit.dst) hostSet.add(hit.dst);
        
        if (hit.timestamp) {
            if (hit.timestamp < firstSeen) firstSeen = hit.timestamp;
            if (hit.timestamp > lastSeen) lastSeen = hit.timestamp;
        }
        
        if (hit.alertId) {
            const alert = timelineEvents.find(e => e.id === hit.alertId);
            if (alert) {
                if (alert.eventType) eventTypeSet.add(alert.eventType);
                if (alert.severity && severityWeights[alert.severity] > severityWeights[maxSeverity]) {
                    maxSeverity = alert.severity;
                }
                if (alert.confidence) {
                    confidenceSum += alert.confidence;
                    confidenceCount++;
                }
            }
        }
    }

    
    if (ioc.severity && severityWeights[ioc.severity] > severityWeights[maxSeverity]) {
        maxSeverity = ioc.severity;
    }

    
    if (ioc.firstSeen && ioc.firstSeen < firstSeen) firstSeen = ioc.firstSeen;
    if (ioc.lastSeen && ioc.lastSeen > lastSeen) lastSeen = ioc.lastSeen;
    if (firstSeen === Infinity) firstSeen = null;
    if (lastSeen === 0) lastSeen = null;

    const hosts = Array.from(hostSet);
    const behaviours = Array.from(eventTypeSet);
    const confidence = confidenceCount > 0 ? Math.round(confidenceSum / confidenceCount) : (ioc.severity ? 70 : 50);

    
    let risk = 'Low';
    const weight = severityWeights[maxSeverity] || 1;
    if (weight >= 4) risk = 'Critical';
    else if (weight >= 3) risk = 'High';
    else if (weight >= 2) risk = 'Medium';
    else risk = 'Low';

    
    if (totalHits >= 50 && risk !== 'Critical') risk = 'High';
    else if (totalHits >= 20 && risk === 'Low') risk = 'Medium';

    
    let assessment = '';
    
    const hasC2 = behaviours.some(b => b.toLowerCase().includes('c2') || b.toLowerCase().includes('beaconing'));
    const hasExfil = behaviours.some(b => b.toLowerCase().includes('exfil'));
    const hasBrute = behaviours.some(b => b.toLowerCase().includes('brute force'));
    const hasRecon = behaviours.some(b => b.toLowerCase().includes('scan'));
    const hasMalware = behaviours.some(b => b.toLowerCase().includes('malware'));
    const hasLateral = behaviours.some(b => b.toLowerCase().includes('lateral'));

    if (hasC2 && hasExfil) assessment = 'This IOC is strongly associated with **data exfiltration via C2 channels**.';
    else if (hasC2) assessment = 'This IOC is strongly associated with **command-and-control activity**.';
    else if (hasExfil) assessment = 'This IOC is strongly associated with **data exfiltration**.';
    else if (hasLateral) assessment = 'This IOC is strongly associated with **lateral movement**.';
    else if (hasBrute) assessment = 'This IOC is strongly associated with **credential brute-force attempts**.';
    else if (hasRecon) assessment = 'This IOC is strongly associated with **reconnaissance and scanning**.';
    else if (hasMalware) assessment = 'This IOC is strongly associated with **malware activity**.';
    else if (behaviours.length > 0) {
        assessment = `This IOC is associated with behaviours such as **${behaviours.slice(0, 3).join(', ')}**.`;
    } else {
        assessment = 'This IOC has been observed in network traffic but without specific behaviour classification.';
    }

    
    let summary = `${assessment} It has been seen **${totalHits}** time${totalHits > 1 ? 's' : ''}`;
    if (hosts.length > 0) {
        summary += ` across **${hosts.length}** host${hosts.length > 1 ? 's' : ''}`;
        if (hosts.length <= 3) {
            summary += ` (${hosts.join(', ')})`;
        } else {
            summary += ` (${hosts.slice(0, 3).join(', ')} and ${hosts.length - 3} more)`;
        }
    }
    summary += '.';

    
    let isActive = false;
    let activeDays = 0;
    let timelineText = 'No timeline data.';
    if (firstSeen && lastSeen) {
        const now = Date.now();
        const daysSinceLast = (now - lastSeen) / (1000 * 60 * 60 * 24);
        isActive = daysSinceLast < 7; 
        activeDays = Math.round((lastSeen - firstSeen) / (1000 * 60 * 60 * 24));
        const firstStr = new Date(firstSeen).toLocaleString();
        const lastStr = new Date(lastSeen).toLocaleString();
        timelineText = `First seen: ${firstStr} · Last seen: ${lastStr} · Active for ${activeDays} day${activeDays > 1 ? 's' : ''}`;
        if (!isActive) timelineText += ' · 🟢 Dormant (no activity in last 7 days)';
        else timelineText += ' · 🔴 Active (seen recently)';
    } else if (firstSeen) {
        timelineText = `First seen: ${new Date(firstSeen).toLocaleString()} · No recent activity.`;
    } else if (lastSeen) {
        timelineText = `Last seen: ${new Date(lastSeen).toLocaleString()}`;
    }

    
    const phaseSet = new Set();
    for (const eventType of behaviours) {
        const stage = STAGE_MAP[eventType] || eventType;
        const phase = PHASE_MAP[stage];
        if (phase) phaseSet.add(phase);
    }
    
    for (const host of hosts) {
        if (hostStages.has(host)) {
            const entry = hostStages.get(host);
            for (const [stage, ts] of entry.stages) {
                const phase = PHASE_MAP[stage];
                if (phase) phaseSet.add(phase);
            }
        }
    }
    const allPhases = PHASE_ORDER; 
    const completed = allPhases.filter(p => phaseSet.has(p));
    const progress = Math.round((completed.length / allPhases.length) * 100);

    
    
    const relatedIOCs = [];
    const iocType = ioc.type;
    const iocValue = ioc.value;
    for (const other of iocs) {
        if (other.id === ioc.id) continue;
        if (other.type === iocType) {
            
            const otherHosts = new Set();
            if (other.hits) {
                other.hits.forEach(h => {
                    if (h.src) otherHosts.add(h.src);
                    if (h.dst) otherHosts.add(h.dst);
                });
            }
            const common = [...hosts].some(h => otherHosts.has(h));
            if (common) {
                relatedIOCs.push(other);
            }
        }
    }
    
    const topRelated = relatedIOCs.slice(0, 5);

    
    const affectedHosts = hosts;
    const linkedIncidents = incidents.filter(inc => {
        return [...inc.hosts].some(h => affectedHosts.includes(h));
    });
    
    const incidentFromAlerts = incidents.filter(inc => {
        return [...inc.alertIds].some(alertId => {
            const alert = timelineEvents.find(e => e.id === alertId);
            return alert && ioc.alertIds && ioc.alertIds.includes(alert.id);
        });
    });
    const allIncidents = [...new Set([...linkedIncidents, ...incidentFromAlerts])];

    return {
        summary: summary,
        assessment: assessment,
        hosts: hosts,
        behaviours: behaviours,
        risk: risk,
        confidence: confidence,
        firstSeen: firstSeen,
        lastSeen: lastSeen,
        isActive: isActive,
        timelineText: timelineText,
        campaignPhases: completed,
        campaignProgress: progress,
        totalPhases: allPhases.length,
        relatedIOCs: topRelated,
        incidents: allIncidents,
        affectedHosts: affectedHosts,
        totalHits: totalHits
    };
}


function renderIocIntelSummary(ioc) {
    const container = document.getElementById('ioc-summary-content');
    if (!container) return;

    const intel = generateIocIntelSummary(ioc);

    
    const riskColor = intel.risk === 'Critical' ? 'var(--danger)' :
                      intel.risk === 'High' ? 'var(--warning)' :
                      intel.risk === 'Medium' ? 'var(--primary)' : 'var(--secondary)';

    
    const confColor = intel.confidence >= 80 ? 'var(--secondary)' :
                      intel.confidence >= 50 ? 'var(--warning)' : 'var(--danger)';

    let html = `
        <div style="font-size: 14px; line-height: 1.6; margin-bottom: 8px;">
            ${intel.summary}
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-top: 8px;">
            <div>
                <strong>Confidence:</strong> <span style="color: ${confColor}; font-weight: 700;">${intel.confidence}%</span>
            </div>
            <div>
                <strong>Risk:</strong> <span style="background: ${riskColor}; color: white; padding: 2px 12px; border-radius: 12px; font-weight: 600;">${intel.risk}</span>
            </div>
            <div>
                <strong>Total Hits:</strong> ${intel.totalHits}
            </div>
        </div>
        ${intel.behaviours.length > 0 ? `
            <div style="margin-top: 8px;">
                <strong>Observed Behaviours:</strong>
                ${intel.behaviours.map(b => `<span style="background: var(--surface); padding: 2px 10px; border-radius: 12px; margin: 2px; display: inline-block; font-size: 12px;">${b}</span>`).join(' ')}
            </div>
        ` : ''}
        <div style="margin-top: 8px;">
            <strong>Timeline:</strong> ${intel.timelineText}
        </div>
        <div style="margin-top: 8px;">
            <strong>Affected Hosts:</strong> ${intel.affectedHosts.length > 0 ? intel.affectedHosts.join(', ') : 'None'}
        </div>
        <div style="margin-top: 8px;">
            <strong>Campaign Progress:</strong> ${intel.campaignPhases.length}/${intel.totalPhases} phases completed
            <div style="width: 100%; height: 8px; background: var(--surface-light); border-radius: 4px; overflow: hidden; margin-top: 4px;">
                <div style="width: ${intel.campaignProgress}%; height: 100%; background: ${intel.campaignProgress >= 80 ? 'var(--secondary)' : intel.campaignProgress >= 50 ? 'var(--warning)' : 'var(--danger)'}; border-radius: 4px;"></div>
            </div>
            <div style="display: flex; gap: 8px; margin-top: 4px; font-size: 12px; color: var(--text-muted);">
                ${PHASE_ORDER.map(phase => {
                    const done = intel.campaignPhases.includes(phase);
                    return `<span style="${done ? 'color: var(--secondary);' : 'color: var(--text-muted);'}">${done ? '✅' : '◻️'} ${phase}</span>`;
                }).join(' ')}
            </div>
        </div>
        ${intel.relatedIOCs.length > 0 ? `
            <div style="margin-top: 8px;">
                <strong>Related IOCs:</strong>
                ${intel.relatedIOCs.map(rel => `<span class="ioc-type-badge" style="cursor: pointer; background: var(--surface); padding: 2px 8px; border-radius: 12px; margin: 2px; display: inline-block; font-size: 12px;" onclick="showIocHits(${rel.id})">${rel.value} (${rel.type})</span>`).join(' ')}
            </div>
        ` : ''}
        ${intel.incidents.length > 0 ? `
            <div style="margin-top: 8px;">
                <strong>Linked Incidents:</strong>
                ${intel.incidents.map(inc => `<span class="priority-badge" style="cursor: pointer; background: var(--surface); padding: 2px 8px; border-radius: 12px; margin: 2px; display: inline-block; font-size: 12px;" onclick="openIncidentDetail(${inc.id})">#${inc.id} (${inc.severity})</span>`).join(' ')}
            </div>
        ` : ''}
    `;

    container.innerHTML = html;
}

const _origShowIocHits = window.showIocHits || function() {};

window.showIocHits = function(iocId) {
    
    if (typeof _origShowIocHits === 'function') {
        _origShowIocHits(iocId);
    } else {
        
        
        const ioc = iocs.find(i => i.id === iocId);
        if (!ioc) return;
        const modal = document.getElementById('ioc-hits-modal');
        const title = document.getElementById('ioc-hits-title');
        const content = document.getElementById('ioc-hits-content');
        title.textContent = `${ioc.value} (${ioc.type})`;
        if (!ioc.hits || ioc.hits.length === 0) {
            content.innerHTML = '<p>No hits recorded yet.</p>';
        } else {
            let html = `<table class="packet-table"><thead><tr><th>Time</th><th>Source</th><th>Destination</th></tr></thead><tbody>`;
            ioc.hits.slice().reverse().forEach(hit => {
                const time = new Date(hit.timestamp).toLocaleString();
                html += `<tr><td>${time}</td><td>${hit.src}</td><td>${hit.dst}</td></tr>`;
            });
            html += `</tbody></table>`;
            content.innerHTML = html;
        }
    }

    const ioc = iocs.find(i => i.id === iocId);
    if (ioc) {
        renderIocIntelSummary(ioc);
    }

    document.getElementById('ioc-hits-modal').classList.remove('hidden');
};

document.getElementById('close-ioc-hits-modal')?.addEventListener('click', () => {
    document.getElementById('ioc-hits-modal').classList.add('hidden');
});
document.getElementById('ioc-hits-modal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
});

window.generateIocIntelSummary = generateIocIntelSummary;
window.renderIocIntelSummary = renderIocIntelSummary;

console.log('✅ Enhanced AI Threat Intelligence Summary for IOCs loaded.');





function renderExecutiveReport() {
    
    document.getElementById('exec-report-timestamp').textContent = new Date().toLocaleString();

    
    const overallRisk = computeOverallRisk();
    document.getElementById('exec-risk-score').textContent = overallRisk.score;
    const riskColor = overallRisk.score >= 80 ? 'var(--danger)' :
                      overallRisk.score >= 50 ? 'var(--warning)' : 'var(--secondary)';
    document.getElementById('exec-risk-score').style.color = riskColor;
    document.getElementById('exec-threat-score').textContent = overallRisk.threatScore;

    
    document.getElementById('exec-incidents').textContent = incidents.length;
    document.getElementById('exec-alerts').textContent = timelineEvents.length;

    
    drawPostureGauge(overallRisk.score);

    
    renderBusinessImpact();

    
    renderMitreCoverageSummary();

    
    renderMonthlyTrend();

    
    renderAInarrative();

    
    renderCampaignSummary();

    
    renderForecast();

    
    renderAIFindings();

    
    renderResponseKPIs();

    
    renderExecutiveRecommendations();
}


function drawPostureGauge(score) {
    const canvas = document.getElementById('exec-posture-gauge');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const cx = w/2, cy = h/2, radius = 45;
    const startAngle = Math.PI * 0.75;
    const endAngle = Math.PI * 2.25;
    const range = endAngle - startAngle;
    const value = Math.min(Math.max(score, 0), 100);
    const angle = startAngle + (value / 100) * range;

    
    ctx.clearRect(0, 0, w, h);

    
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = '#2a2a30';
    ctx.lineWidth = 14;
    ctx.stroke();

    
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, angle);
    const color = score >= 80 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444';
    ctx.strokeStyle = color;
    ctx.lineWidth = 14;
    ctx.stroke();

    
    document.getElementById('exec-posture-text').textContent = Math.round(score);
    const label = document.getElementById('exec-posture-label');
    if (score >= 80) label.textContent = 'Strong Posture';
    else if (score >= 50) label.textContent = 'Moderate Risk';
    else label.textContent = 'High Risk';
    label.style.color = color;
}

function renderBusinessImpact() {
    const container = document.getElementById('exec-business-impact');
    if (!container) return;
    const criticalityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    assets.forEach(a => {
        const c = a.criticality || 'Medium';
        if (criticalityCounts[c] !== undefined) criticalityCounts[c]++;
    });
    const total = assets.length || 1;
    let html = '';
    Object.entries(criticalityCounts).forEach(([label, count]) => {
        const pct = (count / total * 100).toFixed(0);
        const color = label === 'Critical' ? '#ef4444' : label === 'High' ? '#f59e0b' : label === 'Medium' ? '#fbbf24' : '#10b981';
        html += `
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="width: 80px; font-weight: 500;">${label}</span>
                <div style="flex:1; height: 12px; background: var(--surface-light); border-radius: 6px; overflow: hidden;">
                    <div style="width: ${pct}%; height: 100%; background: ${color}; border-radius: 6px;"></div>
                </div>
                <span style="min-width: 40px; text-align: right; font-size: 13px; color: var(--text-muted);">${count}</span>
            </div>
        `;
    });
    container.innerHTML = html;
}

function renderMitreCoverageSummary() {
    const container = document.getElementById('exec-mitre-coverage');
    if (!container) return;
    const totalTechs = Object.keys(MITRE_TECHNIQUES).length;
    let observed = 0;
    const techCounts = {};
    timelineEvents.forEach(e => {
        if (e.mitre) {
            if (!techCounts[e.mitre]) techCounts[e.mitre] = 0;
            techCounts[e.mitre]++;
        }
    });
    observed = Object.keys(techCounts).length;
    const pct = totalTechs > 0 ? Math.round((observed / totalTechs) * 100) : 0;
    const topTechs = Object.entries(techCounts).sort((a,b) => b[1]-a[1]).slice(0, 5);
    let html = `
        <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 8px;">
            <span style="font-size: 28px; font-weight: 700; color: var(--primary);">${pct}%</span>
            <span style="color: var(--text-muted);">of MITRE techniques observed</span>
        </div>
        <div style="width: 100%; height: 8px; background: var(--surface-light); border-radius: 4px; overflow: hidden; margin-bottom: 12px;">
            <div style="width: ${pct}%; height: 100%; background: var(--primary); border-radius: 4px;"></div>
        </div>
        <div style="font-size: 13px;">
            <strong>Top techniques:</strong>
            ${topTechs.length ? topTechs.map(([tech, count]) =>
                `<span class="mitre-badge" style="margin: 2px;">${tech} (${count})</span>`
            ).join(' ') : 'None observed'}
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
            ${observed} unique techniques · ${totalTechs} total in MITRE ATT&CK v14
        </div>
    `;
    container.innerHTML = html;
}

function renderMonthlyTrend() {
    const ctx = document.getElementById('exec-monthly-trend').getContext('2d');
    const now = Date.now();
    const thirtyDaysAgo = now - 30 * 24 * 3600000;
    const dailyCounts = {};
    for (let i = 0; i < 30; i++) {
        const d = new Date(now - i * 24 * 3600000);
        const key = d.toISOString().slice(0,10);
        dailyCounts[key] = 0;
    }
    timelineEvents.forEach(e => {
        const ts = e.eventTimestamp || 0;
        if (ts >= thirtyDaysAgo) {
            const key = new Date(ts).toISOString().slice(0,10);
            if (dailyCounts.hasOwnProperty(key)) dailyCounts[key]++;
        }
    });
    const labels = Object.keys(dailyCounts).sort(); 
    const data = labels.map(k => dailyCounts[k]);
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.map(d => d.slice(5)), 
            datasets: [{
                label: 'Alerts per day',
                data: data,
                backgroundColor: 'rgba(99,102,241,0.6)',
                borderColor: '#6366f1',
                borderWidth: 1,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#9ca3af' } },
                x: { ticks: { color: '#9ca3af', maxTicksLimit: 15 } }
            }
        }
    });
}

function renderCampaignSummary() {
    const container = document.getElementById('exec-campaign-summary');
    if (!container) return;
    
    const campaigns = [];
    const used = new Set();
    incidents.forEach(inc => {
        if (used.has(inc.id)) return;
        const group = [inc];
        used.add(inc.id);
        
        incidents.forEach(other => {
            if (used.has(other.id)) return;
            const commonHosts = [...inc.hosts].filter(h => other.hosts.has(h)).length;
            const commonTechs = [...inc.attackStages].filter(s => other.attackStages.has(s)).length;
            if (commonHosts >= 1 || commonTechs >= 2) {
                group.push(other);
                used.add(other.id);
            }
        });
        if (group.length > 0) campaigns.push(group);
    });

    if (campaigns.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted);">No campaigns identified.</div>';
        return;
    }

    let html = '';
    campaigns.slice(0, 3).forEach((group, idx) => {
        const severity = group.reduce((max, inc) => {
            const w = inc.severity === 'critical' ? 4 : inc.severity === 'high' ? 3 : inc.severity === 'medium' ? 2 : 1;
            return Math.max(max, w);
        }, 0);
        const sevLabel = severity >= 4 ? 'Critical' : severity >= 3 ? 'High' : severity >= 2 ? 'Medium' : 'Low';
        const sevColor = severity >= 4 ? '#ef4444' : severity >= 3 ? '#f59e0b' : severity >= 2 ? '#fbbf24' : '#10b981';
        const hosts = new Set();
        group.forEach(inc => inc.hosts.forEach(h => hosts.add(h)));
        const stages = new Set();
        group.forEach(inc => inc.attackStages.forEach(s => stages.add(s)));
        html += `
            <div style="background: var(--surface-light); border-radius: 8px; padding: 12px; margin-bottom: 12px; border-left: 4px solid ${sevColor};">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <strong>Campaign #${idx+1}</strong>
                    <span style="color: ${sevColor}; font-weight: 600;">${sevLabel}</span>
                </div>
                <div style="font-size: 13px; color: var(--text-muted);">
                    <span>Hosts: ${[...hosts].join(', ') || 'None'}</span>
                    <span style="margin-left: 16px;">Stages: ${[...stages].join(' → ') || 'N/A'}</span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                    ${group.length} incident${group.length > 1 ? 's' : ''} linked · Confidence: ${Math.round(group.reduce((s, inc) => s + (inc.confidence || 50), 0) / group.length)}%
                </div>
            </div>
        `;
    });
    container.innerHTML = html || '<div style="color: var(--text-muted);">No campaigns identified.</div>';
}

function renderForecast() {
    const container = document.getElementById('exec-forecast');
    if (!container) return;
    const activeIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating');
    if (activeIncidents.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted);">No active incidents to forecast.</div>';
        return;
    }
    let html = '';
    activeIncidents.slice(0, 5).forEach(inc => {
        
        const sorted = [...inc.alertIds].map(id => timelineEvents.find(e => e.id === id)).filter(Boolean);
        const alert = sorted.reduce((a, b) => {
            const w = a => a.severity === 'critical' ? 4 : a.severity === 'high' ? 3 : a.severity === 'medium' ? 2 : 1;
            return w(a) > w(b) ? a : b;
        }, sorted[0]);
        if (!alert) return;
        const pred = predictNextAttackStage(alert);
        const prob = pred.probability;
        const next = pred.nextPhase;
        const progress = pred.progress;
        const color = prob >= 70 ? '#ef4444' : prob >= 40 ? '#f59e0b' : '#10b981';
        html += `
            <div style="background: var(--surface-light); border-radius: 8px; padding: 10px; margin-bottom: 10px; border-left: 3px solid ${color};">
                <div style="display: flex; justify-content: space-between;">
                    <strong>Incident #${inc.id}</strong>
                    <span style="font-weight: 600; color: ${color};">${next} (${Math.round(prob)}%)</span>
                </div>
                <div style="font-size: 13px; color: var(--text-muted);">
                    Progress: ${Math.round(progress)}% · Current: ${pred.currentPhase}
                </div>
                <div style="font-size: 12px; color: var(--text-muted);">
                    ${pred.reasoning.slice(0, 2).join(' ')}
                </div>
            </div>
        `;
    });
    container.innerHTML = html || '<div style="color: var(--text-muted);">No predictions available.</div>';
}

function renderAInarrative() {
    const container = document.getElementById('exec-narrative');
    if (!container) return;
    const incidentCount = incidents.length;
    const alertCount = timelineEvents.length;
    const critical = incidents.filter(i => i.severity === 'critical').length;
    const high = incidents.filter(i => i.severity === 'high').length;
    const resolved = incidents.filter(i => i.status === 'resolved').length;

    
    const eventCounts = {};
    timelineEvents.forEach(e => {
        const type = e.eventType;
        eventCounts[type] = (eventCounts[type] || 0) + 1;
    });
    const sortedEvents = Object.entries(eventCounts).sort((a,b) => b[1]-a[1]).slice(0, 3);
    const topEvents = sortedEvents.map(([type, count]) => `${type} (${count})`).join(', ');

    
    const iocMatches = iocs.reduce((s, i) => s + (i.matchCount || 0), 0);
    const exfilAlerts = timelineEvents.filter(e => e.eventType.includes('Exfiltration')).length;

    
    const autoSuccess = actionLogs.filter(l => l.success && l.autoExecute).length;

    
    let summary = `During the last 24 hours, NeoShield processed ${alertCount} security events and identified ${incidentCount} correlated incidents. `;
    if (critical > 0) summary += `Of these, ${critical} reached Critical priority, requiring immediate attention. `;
    if (high > 0) summary += `${high} incidents were classified as High severity. `;
    if (resolved > 0) summary += `${resolved} incidents have been resolved. `;
    if (iocMatches > 0) summary += `The system detected ${iocMatches} matches against known Indicators of Compromise. `;
    if (exfilAlerts > 0) summary += `Potential data exfiltration was detected in ${exfilAlerts} alerts. `;
    if (autoSuccess > 0) summary += `Automated response actions were successfully executed ${autoSuccess} times, reducing manual workload. `;
    if (topEvents) summary += `The most frequent event types were: ${topEvents}. `;
    
    const criticalAssets = assets.filter(a => a.criticality === 'Critical').length;
    if (criticalAssets > 0) {
        const affectedCritical = incidents.filter(inc => [...inc.hosts].some(h => {
            const asset = getAssetByIdentifier(h);
            return asset && asset.criticality === 'Critical';
        })).length;
        summary += `${affectedCritical} critical assets were affected. `;
    }
    
    const avgConf = timelineEvents.reduce((s, e) => s + (e.confidence || 50), 0) / (timelineEvents.length || 1);
    summary += `AI confidence in current incident assessments is ${Math.round(avgConf)}%. `;
    
    const openIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
    if (openIncidents === 0) summary += 'No outstanding incidents remain.';
    else summary += `${openIncidents} incidents remain under investigation.`;

    container.textContent = summary;
}

function exportExecutiveReport(type) {
    
    if (type === 'pdf') {
        document.body.classList.add('print-pdf');
        window.print();
        setTimeout(() => document.body.classList.remove('print-pdf'), 500);
        return;
    }
    if (type === 'soc') {
        
        document.body.classList.add('print-soc');
        window.print();
        setTimeout(() => document.body.classList.remove('print-soc'), 500);
        return;
    }
    if (type === 'board') {
        document.body.classList.add('print-board');
        window.print();
        setTimeout(() => document.body.classList.remove('print-board'), 500);
        return;
    }
    if (type === 'csv') {
        
        const rows = [
            ['Metric', 'Value'],
            ['Alerts Processed', timelineEvents.length],
            ['Incidents Created', incidents.length],
            ['Critical Incidents', incidents.filter(i => i.severity === 'critical').length],
            ['Resolved Incidents', incidents.filter(i => i.status === 'resolved').length],
            ['Open Incidents', incidents.filter(i => i.status === 'open' || i.status === 'investigating').length],
            ['IOC Matches', iocs.reduce((s, i) => s + (i.matchCount || 0), 0)],
            ['Automation Success', actionLogs.filter(l => l.success && l.autoExecute).length],
            ['Mean Time to Acknowledge (min)', computeAlertMetrics().mtta !== null ? computeAlertMetrics().mtta.toFixed(1) : '--'],
            ['Mean Time to Resolve (min)', computeAlertMetrics().mttr !== null ? computeAlertMetrics().mttr.toFixed(1) : '--'],
        ];
        const csvContent = rows.map(r => r.join(',')).join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `executive_metrics_${new Date().toISOString().slice(0,10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('CSV exported.', 'success');
    }
}

function computeOverallRisk() {
    
    let criticalIncidents = incidents.filter(i => i.severity === 'critical').length;
    let highIncidents = incidents.filter(i => i.severity === 'high').length;
    let mediumIncidents = incidents.filter(i => i.severity === 'medium').length;

    
    let iocMatches = iocs.reduce((sum, i) => sum + (i.matchCount || 0), 0);

    
    let uebaAnomalies = Object.values(uebaData).filter(d => (d.score || 0) > 50).length;

    
    const oneHourAgo = Date.now() - 3600000;
    let activeC2 = timelineEvents.filter(e =>
        (e.eventType.includes('C2') || e.eventType.includes('Beaconing')) &&
        (e.eventTimestamp || 0) > oneHourAgo
    ).length;

    
    let riskScore = 0;
    riskScore += Math.min(criticalIncidents * 15, 30); 
    riskScore += Math.min(highIncidents * 8, 20);      
    riskScore += Math.min(iocMatches * 2, 15);         
    riskScore += Math.min(uebaAnomalies * 5, 15);      
    riskScore += Math.min(activeC2 * 10, 20);          
    riskScore = Math.min(riskScore, 100);

    
    let totalSeverityWeight = 0;
    let totalConfidence = 0;
    incidents.forEach(inc => {
        const weight = inc.severity === 'critical' ? 4 :
                       inc.severity === 'high' ? 3 :
                       inc.severity === 'medium' ? 2 : 1;
        totalSeverityWeight += weight;
        totalConfidence += inc.confidence || 50;
    });
    let threatScore = 0;
    if (incidents.length > 0) {
        threatScore = (totalConfidence / incidents.length) * (totalSeverityWeight / (incidents.length * 2.5));
        threatScore = Math.min(threatScore, 100);
    } else {
        
        let alertScore = 0;
        if (timelineEvents.length > 0) {
            let avgConf = timelineEvents.reduce((s, e) => s + (e.confidence || 50), 0) / timelineEvents.length;
            let sevWeight = timelineEvents.reduce((s, e) => s + (e.severity === 'critical' ? 4 : e.severity === 'high' ? 3 : e.severity === 'medium' ? 2 : 1), 0) / timelineEvents.length;
            alertScore = avgConf * (sevWeight / 2.5);
        }
        threatScore = Math.min(alertScore, 100);
    }
    threatScore = Math.round(threatScore);

    return {
        score: Math.round(riskScore),
        threatScore: threatScore
    };
}


function generateExecutiveSummary() {
    const incidentCount = incidents.length;
    const alertCount = timelineEvents.length;
    const criticalIncidents = incidents.filter(i => i.severity === 'critical').length;
    const highIncidents = incidents.filter(i => i.severity === 'high').length;
    const resolvedIncidents = incidents.filter(i => i.status === 'resolved').length;

    
    const iocMatches = iocs.reduce((sum, i) => sum + (i.matchCount || 0), 0);

    
    const autoActions = actionLogs.filter(l => l.success && l.autoExecute).length;
    const manualActions = actionLogs.filter(l => l.success && !l.autoExecute).length;

    
    let topHost = 'unknown';
    let topHostAlerts = 0;
    const hostAlertCount = {};
    timelineEvents.forEach(e => {
        if (e.src) {
            hostAlertCount[e.src] = (hostAlertCount[e.src] || 0) + 1;
            if (hostAlertCount[e.src] > topHostAlerts) {
                topHostAlerts = hostAlertCount[e.src];
                topHost = e.src;
            }
        }
    });

    
    let parts = [];
    if (incidentCount === 0 && alertCount === 0) {
        parts.push('No security events were detected in the last 24 hours. The environment appears to be clean.');
    } else {
        parts.push(`During the last 24 hours, NeoShield processed ${alertCount} security events, resulting in ${incidentCount} correlated incidents.`);

        if (criticalIncidents > 0) {
            parts.push(`Of these, ${criticalIncidents} reached Critical priority, requiring immediate attention.`);
        }
        if (highIncidents > 0) {
            parts.push(`${highIncidents} incidents were classified as High severity.`);
        }
        if (resolvedIncidents > 0) {
            parts.push(`${resolvedIncidents} incidents have been resolved.`);
        }

        
        if (iocMatches > 0) {
            parts.push(`The system detected ${iocMatches} matches against known Indicators of Compromise.`);
        }

        
        if (autoActions > 0) {
            parts.push(`Automated response actions were successfully executed ${autoActions} times, reducing manual workload.`);
        }

        
        if (topHost && topHostAlerts > 1) {
            parts.push(`The most active host was ${topHost}, with ${topHostAlerts} alerts.`);
        }

        
        const highRiskCountries = timelineEvents.filter(e => e.eventType === 'Suspicious Geolocation').length;
        if (highRiskCountries > 0) {
            parts.push(`Suspicious geolocation activity was observed ${highRiskCountries} times.`);
        }

        
        const exfilAlerts = timelineEvents.filter(e => e.eventType.includes('Exfiltration')).length;
        if (exfilAlerts > 0) {
            parts.push(`Potential data exfiltration was detected in ${exfilAlerts} alerts.`);
        } else {
            parts.push('No evidence of data exfiltration was detected.');
        }

        
        const avgConf = timelineEvents.reduce((s, e) => s + (e.confidence || 50), 0) / (timelineEvents.length || 1);
        if (avgConf > 70) {
            parts.push(`AI confidence in current incident assessments is ${Math.round(avgConf)}%.`);
        }
    }

    return parts.join(' ');
}


function renderRiskTrendChart() {
    const ctx = document.getElementById('exec-risk-trend-chart').getContext('2d');
    
    const now = Date.now();
    const oneDayAgo = now - 24 * 3600000;
    const hourlyData = {};
    for (let i = 0; i < 24; i++) {
        const hour = new Date(now - i * 3600000).getHours();
        hourlyData[hour] = { riskSum: 0, count: 0 };
    }

    timelineEvents.forEach(e => {
        const ts = e.eventTimestamp || 0;
        if (ts >= oneDayAgo) {
            const hour = new Date(ts).getHours();
            if (hourlyData[hour]) {
                
                const severityWeight = e.severity === 'critical' ? 4 :
                                       e.severity === 'high' ? 3 :
                                       e.severity === 'medium' ? 2 : 1;
                const risk = (e.confidence || 50) * (severityWeight / 4);
                hourlyData[hour].riskSum += risk;
                hourlyData[hour].count++;
            }
        }
    });

    
    const hours = Object.keys(hourlyData).sort((a,b) => a - b);
    const avgRisks = hours.map(h => {
        const d = hourlyData[h];
        return d.count > 0 ? Math.min(d.riskSum / d.count, 100) : 0;
    });

    
    const labels = hours.map(h => String(h).padStart(2, '0') + ':00');

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Average Risk',
                data: avgRisks,
                borderColor: '#6366f1',
                backgroundColor: 'rgba(99,102,241,0.1)',
                fill: true,
                tension: 0.3,
                pointRadius: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, max: 100, ticks: { color: '#9ca3af' } },
                x: { ticks: { color: '#9ca3af' } }
            }
        }
    });
}


function renderTopThreatsChart() {
    const ctx = document.getElementById('exec-top-threats-chart').getContext('2d');
    const counts = {};
    timelineEvents.forEach(e => {
        const type = e.eventType;
        counts[type] = (counts[type] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 5);
    const labels = sorted.map(([type]) => type);
    const data = sorted.map(([, count]) => count);

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: data,
                backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#10b981', '#6366f1']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#9ca3af' } },
                x: { ticks: { color: '#9ca3af', maxRotation: 45 } }
            }
        }
    });
}


function renderAttackChain() {
    const container = document.getElementById('exec-attack-chain');
    const progressBar = document.getElementById('exec-attack-progress');
    const percentLabel = document.getElementById('exec-attack-percent');

    
    const completedPhases = new Set();
    for (const [host, entry] of hostStages.entries()) {
        for (const [stage, ts] of entry.stages) {
            const phase = PHASE_MAP[stage];
            if (phase) completedPhases.add(phase);
        }
    }
    
    incidents.forEach(inc => {
        inc.attackStages.forEach(phase => completedPhases.add(phase));
    });

    const allPhases = PHASE_ORDER; 
    const progress = Math.round((completedPhases.size / allPhases.length) * 100);
    progressBar.style.width = progress + '%';
    percentLabel.textContent = progress + '%';

    
    let html = '';
    allPhases.forEach(phase => {
        const done = completedPhases.has(phase);
        const icon = done ? '✅' : '◻️';
        const color = done ? 'var(--secondary)' : 'var(--text-muted)';
        html += `
            <span style="padding: 4px 12px; border-radius: 12px; background: ${done ? 'rgba(16,185,129,0.15)' : 'var(--surface-light)'}; border: 1px solid ${color}; color: ${color}; font-size: 13px;">
                ${icon} ${phase}
            </span>
        `;
    });
    container.innerHTML = html;
}


function renderMostTargetedAssets() {
    const container = document.getElementById('exec-targeted-assets');
    const assetMap = {};
    assets.forEach(a => {
        assetMap[a.ip] = {
            hostname: a.hostname,
            risk: a.risk || 0,
            alerts: a.alerts || 0,
            status: a.status
        };
    });

    
    for (const [host, entry] of hostStages.entries()) {
        if (!assetMap[host]) {
            const alertCount = timelineEvents.filter(e => e.src === host || e.dst === host).length;
            const risk = mlInfoMap.get(host)?.score || 0;
            assetMap[host] = {
                hostname: host,
                risk: risk,
                alerts: alertCount,
                status: risk >= 80 ? 'Blocked' : risk >= 50 ? 'Under Investigation' : 'Healthy'
            };
        }
    }

    
    const sorted = Object.values(assetMap).sort((a,b) => b.risk - a.risk || b.alerts - a.alerts).slice(0, 5);

    if (sorted.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center;">No asset data available.</div>';
        return;
    }

    let html = '';
    sorted.forEach(asset => {
        const riskColor = asset.risk >= 80 ? 'var(--danger)' : asset.risk >= 50 ? 'var(--warning)' : 'var(--secondary)';
        html += `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border);">
                <div>
                    <strong>${asset.hostname}</strong>
                    <span style="font-size: 12px; color: var(--text-muted); margin-left: 8px;">${asset.alerts} alerts</span>
                </div>
                <div>
                    <span style="font-weight: 600; color: ${riskColor};">${asset.risk.toFixed(1)}</span>
                    <span style="font-size: 11px; background: ${asset.status === 'Blocked' ? 'var(--danger)' : asset.status === 'Under Investigation' ? 'var(--warning)' : 'var(--secondary)'}; color: white; padding: 2px 8px; border-radius: 12px; margin-left: 8px;">${asset.status}</span>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}


function renderAIFindings() {
    const container = document.getElementById('exec-ai-findings');
    const findings = [];

    
    const iocMatches = iocs.filter(i => (i.matchCount || 0) > 0);
    if (iocMatches.length > 0) {
        const totalMatches = iocMatches.reduce((s, i) => s + (i.matchCount || 0), 0);
        const uniqueIOCs = iocMatches.length;
        findings.push(`• ${totalMatches} IOC matches across ${uniqueIOCs} indicators.`);
    }

    
    const uebaHigh = Object.values(uebaData).filter(d => (d.score || 0) > 50);
    if (uebaHigh.length > 0) {
        findings.push(`• ${uebaHigh.length} hosts exhibit high UEBA anomaly scores, indicating unusual behaviour.`);
    }

    
    const c2Alerts = timelineEvents.filter(e => e.eventType.includes('C2') || e.eventType.includes('Beaconing'));
    if (c2Alerts.length > 0) {
        findings.push(`• ${c2Alerts.length} alerts indicate command-and-control or beaconing activity.`);
    }

    
    const exfilAlerts = timelineEvents.filter(e => e.eventType.includes('Exfiltration'));
    if (exfilAlerts.length > 0) {
        findings.push(`• Potential data exfiltration detected in ${exfilAlerts.length} alerts.`);
    }

    
    const geoAlerts = timelineEvents.filter(e => e.eventType === 'Suspicious Geolocation');
    if (geoAlerts.length > 0) {
        findings.push(`• ${geoAlerts.length} connections to high‑risk countries observed.`);
    }

    
    const lateralAlerts = timelineEvents.filter(e => e.eventType.includes('Lateral'));
    if (lateralAlerts.length > 0) {
        findings.push(`• Lateral movement indicators present in ${lateralAlerts.length} alerts.`);
    }

    
    const autoSuccess = actionLogs.filter(l => l.success && l.autoExecute).length;
    if (autoSuccess > 0) {
        findings.push(`• ${autoSuccess} automated response actions executed successfully.`);
    }

    
    const avgIncidentConf = incidents.reduce((s, i) => s + (i.confidence || 0), 0) / (incidents.length || 1);
    if (incidents.length > 0) {
        findings.push(`• AI confidence in incident correlation is ${Math.round(avgIncidentConf)}%.`);
    }

    
    if (findings.length === 0) {
        findings.push('• No significant findings in the last 24 hours.');
    }

    container.innerHTML = findings.map(f => `<li>${f}</li>`).join('');
}


function renderResponseKPIs() {
    const container = document.getElementById('exec-response-kpis');

    
    const alertsProcessed = timelineEvents.length;

    
    const incidentsCreated = incidents.length;

    
    const metrics = computeAlertMetrics();
    const mtta = metrics.mtta !== null ? metrics.mtta.toFixed(1) : '--';
    const mttr = metrics.mttr !== null ? metrics.mttr.toFixed(1) : '--';

    
    const casesClosed = cases.filter(c => c.status === 'resolved').length;

    
    const autoTotal = actionLogs.filter(l => l.autoExecute).length;
    const autoSuccess = actionLogs.filter(l => l.success && l.autoExecute).length;
    const autoSuccessRate = autoTotal > 0 ? Math.round((autoSuccess / autoTotal) * 100) : 0;

    
    const fpCount = timelineEvents.filter(e => e.status === 'false_positive').length;
    const fpRate = alertsProcessed > 0 ? Math.round((fpCount / alertsProcessed) * 100) : 0;

    const kpis = [
        { label: 'Alerts Processed', value: alertsProcessed },
        { label: 'Incidents Created', value: incidentsCreated },
        { label: 'Mean Time To Detect', value: mtta + 'm' },
        { label: 'Mean Time To Respond', value: mttr + 'm' },
        { label: 'Cases Closed', value: casesClosed },
        { label: 'Automation Success', value: autoSuccessRate + '%' },
        { label: 'False Positive Rate', value: fpRate + '%' }
    ];

    let html = '';
    kpis.forEach(kpi => {
        html += `
            <div style="background: var(--surface-light); padding: 8px 12px; border-radius: 6px; text-align: center;">
                <div style="font-weight: 600; font-size: 18px; color: var(--text);">${kpi.value}</div>
                <div style="font-size: 12px; color: var(--text-muted);">${kpi.label}</div>
            </div>
        `;
    });
    container.innerHTML = html;
}


function renderExecutiveRecommendations() {
    const container = document.getElementById('exec-recommendations-list');

    
    const topAlerts = timelineEvents
        .filter(e => e.severity === 'critical' || e.severity === 'high')
        .slice(0, 5);

    if (topAlerts.length === 0) {
        container.innerHTML = '<li style="color: var(--text-muted);">No critical recommendations at this time.</li>';
        return;
    }

    
    const rec = generateRecommendedActions(topAlerts[0]);
    const actions = rec.actions || [];

    if (actions.length === 0) {
        container.innerHTML = '<li style="color: var(--text-muted);">No specific recommendations generated.</li>';
        return;
    }

    let html = '';
    actions.forEach(action => {
        html += `<li>• ${action}</li>`;
    });
    container.innerHTML = html;
}


const _origSwitchViewExec = window.switchView || function() {};

window.switchView = function(viewId) {
    if (viewId === 'executive') {
        
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        const target = document.getElementById('executive-view');
        if (target) target.classList.remove('hidden');
        
        renderExecutiveReport();
        
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        document.querySelector('.nav-item[data-view="executive"]')?.classList.add('active');
        closeDrawer();
        return;
    }
    
    if (typeof _origSwitchViewExec === 'function') {
        _origSwitchViewExec(viewId);
    }
};

function addExecutiveNavItem() {
    const nav = document.querySelector('.sidebar-nav');
    if (!nav) return;
    
    if (document.querySelector('.nav-item[data-view="executive"]')) return;

    const link = document.createElement('a');
    link.href = '#';
    link.className = 'nav-item';
    link.dataset.view = 'executive';
    link.innerHTML = '<i class="fas fa-file-alt"></i><span>Executive Reports</span>';
    
    nav.appendChild(link);
}

document.addEventListener('DOMContentLoaded', () => {
    addExecutiveNavItem();
    
});


document.getElementById('executive-report-pdf')?.addEventListener('click', function() {
    
    window.print();
});


document.getElementById('executive-refresh')?.addEventListener('click', function() {
    renderExecutiveReport();
    showToast('Executive report refreshed.', 'success');
});




console.log('✅ Executive Reporting module loaded.');
