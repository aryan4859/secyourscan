"""Built-in threat-actor catalogue and the slice of MITRE ATT&CK it uses.

Profiles summarise public reporting (MITRE ATT&CK group pages, CISA
advisories). Technique lists are the well-documented core of each actor's
tradecraft, not every technique ever attributed to it. ``aliases`` include
the group names ransomware leak-site trackers use (``lockbit3``, ``alphv``…),
so ransomware hits and feed activity link to the right profile.

Tenants add their own actors through the API; those are stored in the
``threat_actors`` table and merged with this list.
"""

# Enterprise ATT&CK tactics in kill-chain order.
TACTICS = [
    ("reconnaissance", "Reconnaissance"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

# id: (name, primary tactic, what to do about it on the defender's side)
TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "T1589": ("Gather Victim Identity Information", "reconnaissance", "Watch for leaked staff emails and credentials (Leaks, Asset Exposure)."),
    "T1566": ("Phishing", "initial-access", "Mail filtering, DMARC p=reject, user reporting button."),
    "T1566.001": ("Spearphishing Attachment", "initial-access", "Block macros and risky attachment types at the gateway."),
    "T1566.002": ("Spearphishing Link", "initial-access", "URL rewriting/sandboxing; monitor lookalike domains (Brand Protection)."),
    "T1566.004": ("Spearphishing Voice", "initial-access", "Help-desk identity verification before resets or MFA changes."),
    "T1190": ("Exploit Public-Facing Application", "initial-access", "Patch KEV CVEs on exposed hosts first (Vulnerabilities)."),
    "T1133": ("External Remote Services", "initial-access", "MFA on every VPN/RDP/Citrix gateway; remove exposed RDP (Attack Surface)."),
    "T1078": ("Valid Accounts", "initial-access", "Reset leaked credentials; enforce MFA; alert on impossible travel."),
    "T1078.004": ("Cloud Accounts", "initial-access", "Conditional access and sign-in risk policies for cloud tenants."),
    "T1195.002": ("Compromise Software Supply Chain", "initial-access", "Vendor risk monitoring (Supply Chain); verify update signatures."),
    "T1189": ("Drive-by Compromise", "initial-access", "Browser isolation/patching; block newly registered domains."),
    "T1199": ("Trusted Relationship", "initial-access", "Least-privilege access for MSPs and vendors (Supply Chain)."),
    "T1059.001": ("PowerShell", "execution", "Constrained Language Mode, script block logging, AMSI."),
    "T1059.005": ("Visual Basic", "execution", "Disable Office macros from the internet."),
    "T1204.002": ("Malicious File", "execution", "Application allow-listing; mark-of-the-web enforcement."),
    "T1047": ("Windows Management Instrumentation", "execution", "Alert on remote WMI process creation."),
    "T1505.003": ("Web Shell", "persistence", "File-integrity monitoring on web roots; patch edge apps."),
    "T1098": ("Account Manipulation", "persistence", "Alert on new credentials/roles added to privileged and app accounts."),
    "T1110": ("Brute Force", "credential-access", "Lockout and rate limits; MFA; block password spraying sources."),
    "T1003": ("OS Credential Dumping", "credential-access", "Credential Guard, LSA protection, EDR."),
    "T1003.001": ("LSASS Memory", "credential-access", "Enable LSA protection (RunAsPPL)."),
    "T1003.003": ("NTDS", "credential-access", "Tier-0 isolation of domain controllers; alert on ntdsutil/vssadmin."),
    "T1621": ("Multi-Factor Authentication Request Generation", "credential-access", "Number matching for push MFA; alert on push storms."),
    "T1056.001": ("Keylogging", "collection", "EDR; phishing-resistant MFA (FIDO2) makes typed secrets worthless."),
    "T1027": ("Obfuscated Files or Information", "defense-evasion", "Content inspection and detonation of archives/scripts."),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion", "Tamper protection on EDR; alert when security services stop."),
    "T1550.001": ("Application Access Token", "defense-evasion", "Short token lifetimes; review OAuth app consents."),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement", "Restrict RDP to jump hosts; never expose it to the internet."),
    "T1219": ("Remote Access Software", "command-and-control", "Allow-list remote tools; block AnyDesk/ScreenConnect where unused."),
    "T1071.001": ("Web Protocols", "command-and-control", "Egress filtering through an inspecting proxy; block known C2 (IOC Hunting feeds)."),
    "T1105": ("Ingress Tool Transfer", "command-and-control", "Block downloads of executables from uncategorised sites."),
    "T1090": ("Proxy", "command-and-control", "Watch for SOHO-router and residential-proxy egress; patch edge devices."),
    "T1560": ("Archive Collected Data", "collection", "Alert on bulk archiving (rar/7z) on servers."),
    "T1567": ("Exfiltration Over Web Service", "exfiltration", "DLP and egress monitoring for large uploads."),
    "T1567.002": ("Exfiltration to Cloud Storage", "exfiltration", "Block rclone/MEGA and unsanctioned cloud storage."),
    "T1486": ("Data Encrypted for Impact", "impact", "Offline, immutable backups; tested restores."),
    "T1490": ("Inhibit System Recovery", "impact", "Alert on vssadmin/wbadmin deletion; protect backup consoles."),
    "T1485": ("Data Destruction", "impact", "Offline backups; segmentation of OT and critical systems."),
    "T1561.002": ("Disk Structure Wipe", "impact", "Offline backups and rebuild runbooks."),
}

SECTORS = [
    "Government", "Defense", "Financial Services", "Healthcare", "Manufacturing", "Energy", "Technology",
    "Telecommunications", "Education", "Retail", "Legal", "Transportation", "Construction", "Media", "Hospitality",
    "Cryptocurrency", "NGO",
]

# Region tokens an actor's ``countries`` may use instead of ISO codes.
REGIONS = {
    "*EU": {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU",
            "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"},
    "*NATO": {"AL", "BE", "BG", "CA", "HR", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IT", "LV", "LT", "LU",
              "ME", "NL", "MK", "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "TR", "GB", "US"},
    "*MIDDLE_EAST": {"AE", "BH", "EG", "IL", "IQ", "JO", "KW", "LB", "OM", "QA", "SA", "SY", "TR", "YE"},
    "*LATAM": {"AR", "BO", "BR", "CL", "CO", "CR", "DO", "EC", "GT", "HN", "MX", "PA", "PE", "PY", "SV", "UY", "VE"},
}

ACTORS: list[dict] = [
    {
        "slug": "apt28", "name": "APT28", "kind": "apt", "origin": "Russia", "motivation": "Espionage",
        "aliases": ["Fancy Bear", "Sofacy", "Forest Blizzard", "STRONTIUM", "Sednit"],
        "description": "Russian GRU-attributed group (Unit 26165) targeting governments, militaries and political "
                       "organisations, with heavy use of credential phishing and password spraying.",
        "sectors": ["Government", "Defense", "Media", "Energy", "Transportation", "NGO"],
        "countries": ["US", "UA", "DE", "FR", "GB", "PL", "*EU", "*NATO"],
        "techniques": ["T1566.001", "T1566.002", "T1110", "T1078", "T1190", "T1059.001", "T1071.001", "T1105",
                       "T1027", "T1003", "T1560", "T1589"],
        "malware": ["X-Agent", "Zebrocy", "CHOPSTICK", "GooseEgg", "HeadLace"],
        "references": ["https://attack.mitre.org/groups/G0007/"],
    },
    {
        "slug": "apt29", "name": "APT29", "kind": "apt", "origin": "Russia", "motivation": "Espionage",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes"],
        "description": "Russian SVR-attributed group behind the SolarWinds supply-chain compromise; favours cloud "
                       "identity abuse, OAuth app misuse and password spraying against Microsoft 365 tenants.",
        "sectors": ["Government", "Technology", "NGO", "Defense", "Healthcare"],
        "countries": ["US", "GB", "DE", "*EU", "*NATO"],
        "techniques": ["T1195.002", "T1566.002", "T1078.004", "T1110", "T1098", "T1550.001", "T1059.001",
                       "T1071.001", "T1027", "T1199"],
        "malware": ["SUNBURST", "TEARDROP", "WellMess", "EnvyScout", "WINELOADER"],
        "references": ["https://attack.mitre.org/groups/G0016/"],
    },
    {
        "slug": "sandworm", "name": "Sandworm", "kind": "apt", "origin": "Russia", "motivation": "Sabotage",
        "aliases": ["Sandworm Team", "Seashell Blizzard", "IRIDIUM", "Voodoo Bear"],
        "description": "Russian GRU Unit 74455; responsible for NotPetya and attacks on Ukrainian power grids, "
                       "using destructive wipers against energy and critical infrastructure.",
        "sectors": ["Energy", "Government", "Telecommunications", "Transportation", "Media"],
        "countries": ["UA", "*NATO"],
        "techniques": ["T1190", "T1078", "T1133", "T1059.001", "T1105", "T1485", "T1561.002", "T1490"],
        "malware": ["NotPetya", "Industroyer", "CaddyWiper", "Cyclops Blink", "AcidRain"],
        "references": ["https://attack.mitre.org/groups/G0034/"],
    },
    {
        "slug": "lazarus", "name": "Lazarus Group", "kind": "apt", "origin": "North Korea", "motivation": "Financial, Espionage",
        "aliases": ["HIDDEN COBRA", "Diamond Sleet", "ZINC", "TraderTraitor"],
        "description": "North Korean state group funding the regime through bank heists and cryptocurrency theft; "
                       "uses fake job offers and trojanised software against developers and exchanges.",
        "sectors": ["Cryptocurrency", "Financial Services", "Defense", "Technology"],
        "countries": ["*GLOBAL"],
        "techniques": ["T1566.001", "T1566.002", "T1204.002", "T1195.002", "T1189", "T1059.001", "T1105",
                       "T1071.001", "T1027", "T1486"],
        "malware": ["AppleJeus", "WannaCry", "BLINDINGCAN", "Manuscrypt", "Dtrack"],
        "references": ["https://attack.mitre.org/groups/G0032/"],
    },
    {
        "slug": "kimsuky", "name": "Kimsuky", "kind": "apt", "origin": "North Korea", "motivation": "Espionage",
        "aliases": ["Emerald Sleet", "THALLIUM", "Velvet Chollima", "APT43"],
        "description": "North Korean intelligence collector focused on foreign-policy, nuclear and defence experts, "
                       "mostly through tailored spearphishing and credential harvesting.",
        "sectors": ["Government", "Defense", "Education", "NGO", "Media"],
        "countries": ["KR", "US", "JP"],
        "techniques": ["T1566.001", "T1566.002", "T1059.001", "T1056.001", "T1071.001", "T1105", "T1027", "T1589"],
        "malware": ["BabyShark", "AppleSeed", "GoldDragon"],
        "references": ["https://attack.mitre.org/groups/G0094/"],
    },
    {
        "slug": "apt41", "name": "APT41", "kind": "apt", "origin": "China", "motivation": "Espionage, Financial",
        "aliases": ["Wicked Panda", "BARIUM", "Brass Typhoon", "Winnti"],
        "description": "Chinese group that mixes state espionage with financially motivated intrusions; known for "
                       "supply-chain attacks and rapid exploitation of internet-facing applications.",
        "sectors": ["Technology", "Healthcare", "Telecommunications", "Government", "Education", "Retail"],
        "countries": ["*GLOBAL"],
        "techniques": ["T1190", "T1195.002", "T1505.003", "T1078", "T1059.001", "T1003.001", "T1105",
                       "T1071.001", "T1486"],
        "malware": ["ShadowPad", "Winnti", "PlugX", "KEYPLUG"],
        "references": ["https://attack.mitre.org/groups/G0096/"],
    },
    {
        "slug": "volt-typhoon", "name": "Volt Typhoon", "kind": "apt", "origin": "China", "motivation": "Pre-positioning",
        "aliases": ["Vanguard Panda", "BRONZE SILHOUETTE", "Insidious Taurus"],
        "description": "Chinese state actor pre-positioning in US critical infrastructure with living-off-the-land "
                       "techniques, entering through edge devices and proxying through compromised SOHO routers.",
        "sectors": ["Energy", "Telecommunications", "Transportation", "Government", "Defense"],
        "countries": ["US", "GU"],
        "techniques": ["T1190", "T1078", "T1133", "T1059.001", "T1003.003", "T1090", "T1047"],
        "malware": ["KV-botnet"],
        "references": ["https://attack.mitre.org/groups/G1017/"],
    },
    {
        "slug": "muddywater", "name": "MuddyWater", "kind": "apt", "origin": "Iran", "motivation": "Espionage",
        "aliases": ["Mango Sandstorm", "MERCURY", "Static Kitten", "Seedworm"],
        "description": "Iranian MOIS-attributed group targeting the Middle East and beyond, often delivering "
                       "legitimate remote-access tools through spearphishing.",
        "sectors": ["Government", "Telecommunications", "Energy", "Defense"],
        "countries": ["IL", "SA", "AE", "TR", "*MIDDLE_EAST"],
        "techniques": ["T1566.001", "T1566.002", "T1219", "T1059.001", "T1059.005", "T1027", "T1105"],
        "malware": ["POWERSTATS", "PhonyC2", "MuddyC2Go"],
        "references": ["https://attack.mitre.org/groups/G0069/"],
    },
    {
        "slug": "fin7", "name": "FIN7", "kind": "cybercrime", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["Carbanak", "Sangria Tempest", "ELBRUS"],
        "description": "Financially motivated group that moved from point-of-sale card theft to ransomware "
                       "affiliate work; known for convincing phishing and malicious USB/maldoc lures.",
        "sectors": ["Retail", "Hospitality", "Financial Services", "Technology"],
        "countries": ["US", "*GLOBAL"],
        "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1059.005", "T1071.001", "T1105", "T1027", "T1486"],
        "malware": ["Carbanak", "Lizar", "POWERTRASH", "Diceloader"],
        "references": ["https://attack.mitre.org/groups/G0046/"],
    },
    {
        "slug": "scattered-spider", "name": "Scattered Spider", "kind": "cybercrime", "origin": "US/UK (English-speaking)",
        "motivation": "Financial",
        "aliases": ["Octo Tempest", "UNC3944", "0ktapus", "Muddled Libra"],
        "description": "Young English-speaking crew that social-engineers help desks to reset MFA, then deploys "
                       "ransomware (ALPHV, later others) and extorts large enterprises.",
        "sectors": ["Hospitality", "Retail", "Telecommunications", "Technology", "Financial Services"],
        "countries": ["US", "GB"],
        "techniques": ["T1566.004", "T1621", "T1078", "T1078.004", "T1219", "T1098", "T1567.002", "T1486"],
        "malware": ["ALPHV", "RansomHub"],
        "references": ["https://attack.mitre.org/groups/G1015/"],
    },
    {
        "slug": "lockbit", "name": "LockBit", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["lockbit3", "lockbit2", "lockbit5", "LockBit 3.0", "LockBitSupp"],
        "description": "Ransomware-as-a-service operation that was the most prolific of 2022–2023; disrupted by "
                       "Operation Cronos in 2024 but still active. Affiliates commonly enter through exposed RDP, "
                       "VPNs without MFA and public-facing exploits.",
        "sectors": ["Manufacturing", "Construction", "Retail", "Healthcare", "Legal", "Education", "Government"],
        "countries": ["*GLOBAL"],
        "techniques": ["T1133", "T1078", "T1190", "T1021.001", "T1047", "T1562.001", "T1567.002", "T1486", "T1490"],
        "malware": ["LockBit", "StealBit"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"],
    },
    {
        "slug": "alphv", "name": "ALPHV / BlackCat", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["alphv", "blackcat", "Noberus"],
        "description": "Rust-based RaaS that exit-scammed in 2024 after the Change Healthcare attack. Affiliates "
                       "(including Scattered Spider) leaned on stolen credentials and help-desk social engineering.",
        "sectors": ["Healthcare", "Financial Services", "Manufacturing", "Legal"],
        "countries": ["US", "*GLOBAL"],
        "techniques": ["T1078", "T1566.004", "T1021.001", "T1562.001", "T1567", "T1486", "T1490"],
        "malware": ["BlackCat", "ExMatter"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"],
    },
    {
        "slug": "clop", "name": "Cl0p", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["clop", "cl0p", "TA505", "Lace Tempest"],
        "description": "Extortion group that mass-exploits zero-days in managed file-transfer software (Accellion, "
                       "GoAnywhere, MOVEit, Cleo) and steals data, often without encrypting.",
        "sectors": ["Financial Services", "Healthcare", "Education", "Government", "Technology"],
        "countries": ["*GLOBAL"],
        "techniques": ["T1190", "T1505.003", "T1567", "T1486", "T1071.001"],
        "malware": ["Cl0p", "LEMURLOOT", "FlawedAmmyy"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
                       "https://attack.mitre.org/groups/G0092/"],
    },
    {
        "slug": "akira", "name": "Akira", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["akira", "Storm-1567"],
        "description": "RaaS active since 2023 that frequently gets in through Cisco and SonicWall VPNs without MFA, "
                       "then exfiltrates with rclone before encrypting Windows and ESXi hosts.",
        "sectors": ["Manufacturing", "Education", "Construction", "Retail", "Healthcare"],
        "countries": ["US", "CA", "GB", "DE", "*GLOBAL"],
        "techniques": ["T1133", "T1078", "T1110", "T1219", "T1021.001", "T1003.001", "T1567.002", "T1486", "T1490"],
        "malware": ["Akira", "Megazord"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
    },
    {
        "slug": "play", "name": "Play", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["play", "playcrypt", "Balloonfly"],
        "description": "Double-extortion group exploiting FortiOS and Exchange (ProxyNotShell) flaws and valid "
                       "accounts; uses intermittent encryption.",
        "sectors": ["Manufacturing", "Government", "Legal", "Technology", "Retail"],
        "countries": ["US", "*LATAM", "*EU"],
        "techniques": ["T1190", "T1078", "T1133", "T1562.001", "T1560", "T1486", "T1490"],
        "malware": ["Play", "Grixba"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"],
    },
    {
        "slug": "qilin", "name": "Qilin", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["qilin", "agenda", "Water Galura"],
        "description": "RaaS with Go and Rust lockers that has hit hospitals and pathology services; enters via "
                       "phishing and VPN credentials, and has stolen browser-stored credentials at scale.",
        "sectors": ["Healthcare", "Manufacturing", "Education", "Legal"],
        "countries": ["*GLOBAL"],
        "techniques": ["T1566", "T1133", "T1078", "T1059.001", "T1562.001", "T1486", "T1490"],
        "malware": ["Qilin", "Agenda"],
        "references": ["https://www.ransomware.live/group/qilin"],
    },
    {
        "slug": "blackbasta", "name": "Black Basta", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["blackbasta", "black basta"],
        "description": "RaaS linked to former Conti members; uses email bombing followed by Teams/phone calls posing "
                       "as IT support to get remote access, then Qakbot/Cobalt Strike and encryption.",
        "sectors": ["Healthcare", "Manufacturing", "Construction", "Retail"],
        "countries": ["US", "DE", "*EU"],
        "techniques": ["T1566", "T1566.004", "T1219", "T1047", "T1021.001", "T1562.001", "T1486", "T1490"],
        "malware": ["Black Basta", "QakBot", "Cobalt Strike"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"],
    },
    {
        "slug": "ransomhub", "name": "RansomHub", "kind": "ransomware", "origin": "Russia-speaking", "motivation": "Financial",
        "aliases": ["ransomhub", "Cyclops", "Knight"],
        "description": "RaaS that absorbed many ALPHV and LockBit affiliates in 2024, using phishing, password "
                       "spraying and exploits of edge devices.",
        "sectors": ["Healthcare", "Government", "Manufacturing", "Financial Services", "Energy"],
        "countries": ["US", "*GLOBAL"],
        "techniques": ["T1566", "T1110", "T1190", "T1078", "T1562.001", "T1567.002", "T1486", "T1490"],
        "malware": ["RansomHub", "EDRKillShifter"],
        "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"],
    },
]
