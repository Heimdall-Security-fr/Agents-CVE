/*
  Heimdall — règles YARA par défaut, distribuées aux agents par le serveur.

  Elles visent des techniques courantes et peu ambiguës (webshells, shells inversés,
  vol d'identifiants, chargeurs PowerShell, mineurs, rançongiciels). Chaque règle porte :
    severity    : low | medium | high | critical (gravité de l'alerte)
    description : texte affiché dans le dashboard
  Ajoutez vos propres jeux (ou des jeux publics, ex. YARA-Forge) depuis la page
  Surveillance du dashboard ; ce fichier n'est pas à modifier.
*/

rule Heimdall_Mimikatz
{
    meta:
        severity = "critical"
        description = "Mimikatz ou dérivé (vol d'identifiants Windows)"
    strings:
        $a1 = "sekurlsa::logonpasswords" ascii wide nocase
        $a2 = "lsadump::sam" ascii wide nocase
        $a3 = "kerberos::golden" ascii wide nocase
        $a4 = "privilege::debug" ascii wide nocase
        $b1 = "gentilkiwi" ascii wide nocase
        $b2 = "mimikatz" ascii wide nocase
    condition:
        2 of ($a*) or (1 of ($a*) and 1 of ($b*))
}

rule Heimdall_Credential_Dumper_Tools
{
    meta:
        severity = "high"
        description = "Outil d'extraction de mots de passe (LaZagne, Rubeus, SharpHound…)"
    strings:
        $s1 = "laZagne" ascii wide nocase
        $s2 = "Rubeus" ascii wide fullword
        $s3 = "SharpHound" ascii wide nocase
        $s4 = "asreproast" ascii wide nocase
        $s5 = "kerberoast" ascii wide nocase
    condition:
        2 of them
}

rule Heimdall_PHP_Webshell
{
    meta:
        severity = "critical"
        description = "Webshell PHP (exécution de code reçu par requête HTTP)"
    strings:
        $open = "<?" ascii
        $e1 = /(eval|assert)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)?\s*\(?\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e3 = /preg_replace\s*\(\s*['"][^'"]*\/e['"]\s*,\s*\$_(POST|GET|REQUEST)/ nocase
        $e4 = /create_function\s*\([^)]*\$_(POST|GET|REQUEST)/ nocase
    condition:
        $open and any of ($e*) and filesize < 2MB
}

rule Heimdall_JSP_ASPX_Webshell
{
    meta:
        severity = "critical"
        description = "Webshell JSP/ASPX (commande système depuis un paramètre HTTP)"
    strings:
        $j1 = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/ nocase
        $j2 = /ProcessBuilder\s*\([^)]*request\.getParameter/ nocase
        $a1 = /Process\.Start\s*\([^)]*Request(\.Form|\.QueryString|\.Params|\[)/ nocase
        $a2 = /eval\s*\(\s*Request(\.Item)?\s*\[/ nocase
    condition:
        any of them and filesize < 2MB
}

rule Heimdall_PowerShell_Reverse_Shell
{
    meta:
        severity = "critical"
        description = "Shell inversé PowerShell (connexion TCP + exécution des commandes reçues)"
    strings:
        $tcp = "Net.Sockets.TCPClient" ascii wide nocase
        $stream = "GetStream" ascii wide nocase
        $iex1 = "iex" ascii wide nocase fullword
        $iex2 = "Invoke-Expression" ascii wide nocase
        $out = "Out-String" ascii wide nocase
    condition:
        $tcp and $stream and ($iex1 or $iex2) and $out
}

rule Heimdall_Unix_Reverse_Shell_Script
{
    meta:
        severity = "critical"
        description = "Script de shell inversé (bash, python, perl, netcat)"
    strings:
        $b = /(bash|sh)\s+-i\s*[>&]+\s*\/dev\/tcp\// ascii
        $p = /socket\.socket\s*\(.{0,200}\.connect\s*\(.{0,300}(subprocess|pty\.spawn|os\.dup2)/ ascii
        $pl = /use\s+Socket;.{0,300}exec\s*\(\s*["']\/bin\/(ba)?sh/ ascii
        $nc = /\b(nc|ncat|netcat)\b[^\n]{0,60}\s-e\s+\/bin\/(ba)?sh/ ascii
    condition:
        any of them and filesize < 5MB
}

rule Heimdall_PowerShell_Downloader
{
    meta:
        severity = "high"
        description = "Chargeur PowerShell (téléchargement puis exécution en mémoire)"
    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadData" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "Net.WebClient" ascii wide nocase
        $x1 = "IEX" ascii wide nocase fullword
        $x2 = "Invoke-Expression" ascii wide nocase
        $x3 = "Reflection.Assembly]::Load" ascii wide nocase
        $x4 = "FromBase64String" ascii wide nocase
    condition:
        any of ($d*) and 2 of ($x*)
}

rule Heimdall_AMSI_Bypass
{
    meta:
        severity = "critical"
        description = "Contournement de l'AMSI (désactive l'analyse antivirus des scripts)"
    strings:
        $a1 = "amsiInitFailed" ascii wide nocase
        $a2 = "AmsiScanBuffer" ascii wide nocase
        $a3 = "System.Management.Automation.AmsiUtils" ascii wide nocase
    condition:
        any of them
}

rule Heimdall_Coin_Miner
{
    meta:
        severity = "high"
        description = "Mineur de cryptomonnaie"
    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $s3 = "--donate-level" ascii wide
        $s4 = "cryptonight" ascii wide nocase
        $s5 = "randomx" ascii wide nocase fullword
        $s6 = "xmrig" ascii wide nocase
    condition:
        2 of them
}

rule Heimdall_Ransom_Note
{
    meta:
        severity = "critical"
        description = "Note de rançon ou chiffrement de fichiers"
    strings:
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "all your files are encrypted" ascii wide nocase
        $n3 = "vos fichiers ont été chiffrés" ascii wide nocase
        $n4 = "to decrypt your files" ascii wide nocase
        $p1 = "bitcoin" ascii wide nocase
        $p2 = ".onion" ascii wide nocase
        $p3 = "private key" ascii wide nocase
    condition:
        any of ($n*) and any of ($p*)
}

rule Heimdall_Backup_Destruction
{
    meta:
        severity = "high"
        description = "Script ou programme qui détruit les sauvegardes Windows (typique des rançongiciels)"
    strings:
        $v1 = /vssadmin(\.exe)?\s+delete\s+shadows/ ascii wide nocase
        $v2 = /wmic(\.exe)?\s+shadowcopy\s+delete/ ascii wide nocase
        $v3 = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+recoveryenabled\s+no/ ascii wide nocase
        $v4 = /wbadmin(\.exe)?\s+delete\s+catalog/ ascii wide nocase
    condition:
        any of them
}

rule Heimdall_Malicious_Shortcut
{
    meta:
        severity = "high"
        description = "Raccourci (.lnk) qui lance PowerShell caché ou encodé"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $ps = "powershell" ascii wide nocase
        $h1 = "-w hidden" ascii wide nocase
        $h2 = "-windowstyle hidden" ascii wide nocase
        $h3 = "-enc" ascii wide nocase fullword
        $h4 = "-encodedcommand" ascii wide nocase
    condition:
        $lnk at 0 and $ps and any of ($h*) and filesize < 1MB
}

rule Heimdall_Linux_Persistence_Script
{
    meta:
        severity = "high"
        description = "Script qui installe une persistance (cron, clé SSH, ld.so.preload) puis télécharge du code"
    strings:
        $p1 = "/etc/ld.so.preload" ascii
        $p2 = "authorized_keys" ascii
        $p3 = "crontab -" ascii
        $p4 = "/etc/cron.d/" ascii
        $d1 = /(curl|wget)\s[^\n]{0,200}\|\s*(ba)?sh/ ascii
        $d2 = /chattr\s+\+i/ ascii
    condition:
        any of ($p*) and any of ($d*) and filesize < 1MB
}
