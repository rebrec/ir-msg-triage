# msg_triage.py

Outil de **triage Incident Response** pour les emails suspects aux formats `.msg`
(Outlook/OLE) et `.eml` (RFC822).

Il extrait et présente en un coup d'œil tout ce qui est nécessaire à la qualification
d'un email de phishing / BEC / malware, **sans jamais rien exécuter** : pas d'ouverture
dans un client mail, pas d'exécution de macro, pas de requête réseau.

---

## Ce que fait l'outil

| Volet | Détail |
|---|---|
| **Métadonnées** | Sujet, date, destinataire, Message-ID |
| **Détection de spoofing** | Compare l'expéditeur **affiché**, l'en-tête `From`, le `Reply-To` et le `Return-Path` — une divergence est un signal fort |
| **Authentification** | Résultats **SPF / DKIM / DMARC** + chemin `Received` complet (remonter à l'origine réelle) |
| **IOCs** | URLs, adresses IP et emails extraits du corps, dédoublonnés et triés |
| **Pièces jointes** | Nom, taille, hashes **MD5 / SHA1 / SHA256** (à soumettre à VirusTotal / MISP) |
| **Extensions à risque** | Flag `[!] RISQUE` sur ~30 extensions dangereuses (`.exe`, `.js`, `.vbs`, `.hta`, `.lnk`, `.docm`, `.iso`, …) |
| **Macros VBA** | Scan des pièces jointes Office via `oletools` : détecte la présence de macros et remonte les indicateurs **Suspicious / AutoExec / IOC** |
| **Corps du message** | Version texte brute **et** version HTML d'origine |
| **Formats de sortie** | Terminal (défaut), **HTML**, **JSON** |

### Sécurité : defanging et sandbox

Tout ce qui est affiché est **défangé** : les schémas `http://` / `https://` deviennent
`hxxp://` / `hxxps://` dans les IOCs, le corps texte, le corps HTML et les en-têtes bruts.
Les liens ne sont donc jamais cliquables, y compris les attributs `href`/`src` du corps HTML.

Les **points sont conservés** (`hxxps://login.phish-acme.ru/verify` et non
`login[.]phish-acme[.]ru`) pour que les IOCs restent copiables-collables directement dans
un ticket, un SIEM ou un bac à sable.

Dans le rapport HTML, le corps d'origine est rendu dans une **iframe `sandbox`** :
scripts et accès réseau bloqués — aucun risque de beacon de tracking ou de pixel espion.

---

## Prérequis

- Python 3.8+
- `extract-msg` — **uniquement pour les fichiers `.msg`** (import paresseux : les `.eml`
  fonctionnent sans)
- `oletools` — optionnel, pour le scan de macros VBA

```bash
pip install extract-msg oletools
```

Les `.eml` sont traités par le module `email` de la bibliothèque standard : aucune
dépendance requise.

---

## Usage

```
python3 msg_triage.py <fichier.msg|fichier.eml> [--html FICHIER] [--json] [--dump-dir DOSSIER]
```

Le format est **détecté automatiquement** via l'extension.

| Option | Effet |
|---|---|
| *(aucune)* | Rapport lisible dans le terminal |
| `--html FICHIER` | Génère un rapport HTML autonome |
| `--json` | Sortie JSON brute (pipeline, SIEM, enrichissement) |
| `--dump-dir DOSSIER` | Extrait les pièces jointes sur disque (écriture seule, aucune exécution) |
| `--all` | **Génère tous les livrables** dans `output/<nom-normalisé>/` (voir ci-dessous) |

### Le mode `--all`

Produit l'ensemble des exports en une seule commande, dans un dossier dédié par email
analysé. L'arborescence est créée automatiquement :

```
output/
└── Facture_Villard_copie/          <- nom du fichier source, normalisé
    ├── rapport.html                 rapport HTML (corps en iframe sandbox)
    ├── rapport.txt                  rapport texte
    ├── rapport.json                 export JSON complet
    ├── iocs.txt                     IOCs défangés (URLs / IPs / emails / hashes)
    ├── headers.txt                  en-têtes SMTP bruts
    └── attachments/                 pièces jointes extraites
        └── Facture_Ete_n42.exe
```

`output/` est créé à la racine du dossier de l'outil (à côté de `msg_triage.py`), quel
que soit le répertoire depuis lequel la commande est lancée.

Le nom du sous-dossier est **normalisé** depuis le nom du fichier source : accents
translittérés, espaces et caractères spéciaux remplacés par `_` — `Facture Villard
(copie).eml` devient `Facture_Villard_copie`. Idem pour les noms de pièces jointes.
Aucun risque de casse lors de la création des dossiers.

En fin d'exécution, la liste de tout ce qui a été créé est affichée avec les chemins
relatifs :

```
Export termine -> output/Facture_Villard_copie/

  output/Facture_Villard_copie/rapport.html                      rapport HTML (corps en iframe sandbox)
  output/Facture_Villard_copie/rapport.txt                       rapport texte
  output/Facture_Villard_copie/rapport.json                      export JSON complet
  output/Facture_Villard_copie/iocs.txt                          IOCs defanges (URLs/IPs/emails/hashes)
  output/Facture_Villard_copie/headers.txt                       en-tetes SMTP bruts
  output/Facture_Villard_copie/attachments/Facture_Ete_n42.exe   piece jointe (17 o)

6 fichier(s) cree(s).
```

> `output/` est dans le `.gitignore` : les artefacts extraits (potentiellement
> malveillants) ne doivent pas être versionnés.

### Exemples

**Triage rapide dans le terminal**
```bash
python3 msg_triage.py suspect.msg
```

**Analyse complète, tous exports générés**
```bash
python3 msg_triage.py suspect.eml --all
```

**Traiter un lot d'emails en analyse complète**
```bash
for f in ./quarantaine/*.eml; do python3 msg_triage.py "$f" --all; done
```

**Rapport HTML à joindre à un ticket**
```bash
python3 msg_triage.py suspect.eml --html rapport.html
```

**Extraire les pièces jointes pour analyse approfondie**
```bash
python3 msg_triage.py suspect.msg --dump-dir ./pj
# puis, par exemple :
sha256sum ./pj/*
```

**Récupérer uniquement les URLs pour un blocage en masse**
```bash
python3 msg_triage.py suspect.eml --json | jq -r '.iocs.urls[]'
```

**Vérifier les hashes de PJ contre VirusTotal**
```bash
python3 msg_triage.py suspect.msg --json | jq -r '.attachments[] | "\(.sha256)  \(.name)"'
```

**Traiter un lot d'emails**
```bash
for f in ./quarantaine/*.eml; do
  python3 msg_triage.py "$f" --html "rapports/$(basename "$f" .eml).html"
done
```

---

## Exemple de sortie

```
======================================================================
  TRIAGE IR : Votre facture en attente
======================================================================
Date          : Tue, 24 Jun 2026 09:12:00 +0200
From (affiche): Service Compta <compta@acme-invoices.com>
From (entete) : Service Compta <compta@acme-invoices.com>
Reply-To      : no-reply@phish-acme.ru
Return-Path   : bounce@phish-acme.ru

-- Authentification --
SPF   : Fail (sender IP is 203.0.113.9)
DKIM  : fail
DMARC : fail

-- IOCs (defanged) --
URLs   : 2
   hxxp://203.0.113.9/x
   hxxps://login.phish-acme.ru/verify
IPs    : 203.0.113.9

-- Pieces jointes (1) --
 * facture.exe (17 o)  [!] RISQUE
     sha256: aebe55cf9cb752053dadf4de33348fdd25e1db0c95881febe80f181a34b051e5
```

Lecture : SPF/DKIM/DMARC en échec, un `Reply-To` sur un domaine différent de l'expéditeur
affiché, et une pièce jointe exécutable — faisceau d'indices convergents.

---

## Notes d'interprétation

- **SPF/DKIM/DMARC en `pass` n'innocente pas un email.** Cela prouve seulement que
  l'expéditeur est autorisé pour ce domaine. Un compte légitime **compromis** (fraude
  au président / BEC) produira un `pass` parfait — dans ce cas, l'attention doit se
  porter sur les URLs et le contenu.
- Un `Reply-To` ou `Return-Path` divergent du `From` affiché est un marqueur classique
  de tentative de détournement de réponse.
- Les mails sans corps texte (HTML uniquement) voient leur version texte **dérivée du
  HTML**, signalée par le préfixe `[derive du HTML]`.

---

## Structure de la sortie JSON

```jsonc
{
  "file": "suspect.eml",
  "file_hashes":  { "md5": "...", "sha1": "...", "sha256": "...", "size": 12345 },
  "subject": "...", "date": "...",
  "sender_display": "...", "from": "...", "reply_to": "...", "return_path": "...",
  "to": "...", "message_id": "...",
  "auth_results": { "spf": "...", "dkim": "pass", "dmarc": "pass", "received_path": [] },
  "iocs":         { "urls": [], "ips": [], "emails": [] },
  "attachments":  [ { "name": "...", "ext": ".exe", "risky": true,
                      "md5": "...", "sha256": "...", "size": 0,
                      "vba_macros": true, "vba_suspicious": [] } ],
  "raw_headers": "...", "body_text": "...", "body_html": "..."
}
```

---

## Avertissement

Les pièces jointes extraites avec `--dump-dir` sont **potentiellement malveillantes**.
Ne les ouvrez jamais sur un poste de production : utilisez une machine virtuelle isolée
ou un bac à sable dédié.
