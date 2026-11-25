"""Técnicas do MITRE ATT&CK usadas pelas regras de detecção."""

TECHNIQUES = {
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1087": "Account Discovery",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1083": "File and Directory Discovery",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1190": "Exploit Public-Facing Application",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, tid)


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
