// Static rules shipped with SecYourScan. Tenants add their own through
// /yara/rules. Each rule's `score` meta is added to the leak's rule score
// (capped at 100); a rule without one counts 10. `category` feeds triage.

rule private_key {
    meta:
        description = "PEM private key (RSA / EC / OpenSSH / generic)"
        score = 60
        category = "SOURCE"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $ssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule cloud_credentials {
    meta:
        description = "Cloud provider access keys"
        score = 55
        category = "SOURCE"
    strings:
        $aws = /AKIA[0-9A-Z]{16}/
        $gcp = /AIza[0-9A-Za-z\-_]{35}/
        $gh = /gh[pousr]_[A-Za-z0-9]{36}/
        $slack = /xox[baprs]-[0-9A-Za-z-]{10,48}/
        $stripe = /sk_live_[0-9a-zA-Z]{24,}/
    condition:
        any of them
}

rule generic_api_key {
    meta:
        description = "Assigned API key or auth token"
        score = 30
        category = "SOURCE"
    strings:
        $api_key = /api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,64}/ nocase
        $auth_token = /auth[_-]?token\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,64}/ nocase
    condition:
        any of them
}

rule combo_list {
    meta:
        description = "Email:password combo list (five or more pairs)"
        score = 50
        category = "CREDENTIALS"
    strings:
        $pair = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[:;|][^\s]{4,}/
    condition:
        #pair >= 5
}

rule database_dump {
    meta:
        description = "SQL dump of a user table"
        score = 40
        category = "PII"
    strings:
        $create = /CREATE TABLE [`"]?(users|accounts|customers|members)/ nocase
        $insert = /INSERT INTO [`"]?(users|accounts|customers|members)/ nocase
        $hash = /\$2[aby]\$\d{2}\$[.\/A-Za-z0-9]{53}/
    condition:
        any of ($create, $insert) or #hash >= 3
}

rule leak_marketplace_language {
    meta:
        description = "Typical sale/dump wording from leak forums"
        score = 15
        category = "OTHER"
    strings:
        $a = "fresh dump" nocase
        $b = "combolist" nocase
        $c = "stealer logs" nocase
        $d = "database leak" nocase
        $e = "full db" nocase
        $f = "fullz" nocase
    condition:
        any of them
}
