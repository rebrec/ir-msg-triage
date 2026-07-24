# msg_triage.py

Outil de **triage Incident Response** pour les emails suspects aux formats `.msg`
(Outlook/OLE) et `.eml` (RFC822).

Il extrait et présente en un coup d'œil tout ce qui est nécessaire à la qualification
d'un email de phishing / BEC / malware, **sans jamais rien exécuter** : pas d'ouverture
dans un client mail, pas d'exécution de macro, pas de requête réseau.

---

## Installation rapide

```bash
git clone https://github.com/rebrec/ir-msg-triage.git
cd ir-msg-triage

python3 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate

pip install extract-msg oletools
```

Puis, pour vérifier que tout est en place :

```bash
python3 msg_triage.py --help
```

L'outil est un **script autonome** : aucune installation supplémentaire, il s'exécute
directement depuis le dossier cloné. Les deux dépendances ci-dessus sont d'ailleurs
optionnelles — voir [Prérequis](#prérequis) — un fichier `.eml` s'analyse sans rien
installer du tout.

---

## Ce que fait l'outil

| Volet | Détail |
|---|---|
| **Métadonnées** | Sujet, date, destinataire, Message-ID |
| **Détection de spoofing** | Compare l'expéditeur **affiché**, l'en-tête `From`, le `Reply-To` et le `Return-Path` — une divergence est un signal fort |
| **Authentification** | Résultats **SPF / DKIM / DMARC** + chemin `Received` complet (remonter à l'origine réelle) |
| **IOCs contextualisés** | URLs, IPs et emails extraits des **en-têtes et des deux corps**, chacun annoté de sa provenance, d'un type [MISP](#vocabulaire-des-iocs) et d'un extrait du source |
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
    ├── iocs.txt                     IOCs défangés actionnables (URLs / IPs / emails / hashes)
    ├── headers.txt                  en-têtes SMTP bruts
    ├── corps_html_source.txt        source HTML défangée, greppable
    └── attachments/                 pièces jointes extraites
        └── Facture_Ete_n42.exe
```

> `corps_html_source.txt` porte volontairement l'extension `.txt` : un `.html` s'ouvrirait
> dans un navigateur au double-clic et **exécuterait ses scripts**, que le défangage ne
> neutralise pas.

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
  output/Facture_Villard_copie/corps_html_source.txt             source HTML defangee (greppable)
  output/Facture_Villard_copie/attachments/Facture_Ete_n42.exe   piece jointe (17 o)

7 fichier(s) cree(s).
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

**Récupérer uniquement les URLs actionnables pour un blocage en masse**
```bash
python3 msg_triage.py suspect.eml --json | jq -r '.iocs.urls[] | select(.to_ids) | .value'
```

**Voir d'où vient chaque IOC**
```bash
python3 msg_triage.py suspect.eml --json \
  | jq -r '.iocs.urls[] | "\(.value)\n    \(.context)\n    \(.snippet)"'
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

URLs : 2 actionnable(s), 1 ecarte(s)
   hxxps://login.phish-acme.ru/verify
      [url] Lien cliquable dans le corps HTML
   hxxp://203.0.113.9/x
      [url] Image distante (pixel de tracage possible)
   (ecarte) hxxp://www.w3.org/1999/xhtml  -> namespace XML/DTD - pas un IOC

IPs : 1 actionnable(s)
   203.0.113.9
      [ip-src] IP emettrice declaree SPF (SPF Fail)

Emails : 2 actionnable(s), 1 ecarte(s)
   compta@acme-invoices.com
      [email-src] Expediteur (From)
   no-reply@phish-acme.ru
      [email-reply-to] Adresse de reponse (Reply-To) - domaine different du From, detournement de reponse possible
   (ecarte) victime@exemple.fr  -> destinataire (victime) - ne pas bloquer

-- Pieces jointes (1) --
 * facture.exe (17 o)  [!] RISQUE
     sha256: aebe55cf9cb752053dadf4de33348fdd25e1db0c95881febe80f181a34b051e5
```

Lecture : SPF/DKIM/DMARC en échec, un `Reply-To` sur un domaine différent de l'expéditeur
affiché, et une pièce jointe exécutable — faisceau d'indices convergents.

---

## Vocabulaire des IOCs

Chaque IOC répond à trois questions : **quoi**, **d'où il vient**, et **est-il exploitable
en détection**. Le vocabulaire suit le modèle [MISP](https://www.misp-project.org/), de
façon à rester importable dans une instance MISP sans retraduction.

### Types et catégories

Alignés sur l'objet `email` de `misp-objects` :

| Type | Utilisé pour | Catégorie MISP |
|---|---|---|
| `ip-src` | IP émettrice, IP d'un saut `Received` | Network activity |
| `url` | URLs, quelle que soit leur provenance | Payload delivery |
| `email` | adresse citée dans un corps ou un nom de PJ | Payload delivery |
| `email-src` | `From`, `Return-Path` | Payload delivery |
| `email-dst` | `To`, `Cc` | Payload delivery |
| `email-reply-to` | `Reply-To` | Payload delivery |
| `email-message-id` | `Message-ID` | Payload delivery |

### Origines

C'est ce qui permet de **retrouver un IOC dans le message** — un lien cliquable et une URL
cachée dans une métadonnée n'ont pas la même portée.

| Origine | Signification |
|---|---|
| `header.from`, `header.sender_display` | Expéditeur |
| `header.to`, `header.cc` | Destinataires |
| `header.reply_to`, `header.return_path` | Redirection de réponse, chemin de retour |
| `header.message_id` | Identifiant du message |
| `header.received_spf` | IP émettrice déclarée par `Received-SPF` |
| `header.received[N]` | Saut `Received` n°N (le dernier est le plus ancien) |
| `body.text` | Corps texte |
| `body.html.text` | Texte visible du corps HTML |
| `body.html.href` | Lien cliquable |
| `body.html.img` | Image distante — pixel de traçage possible |
| `body.html.meta[<prop>]` | Métadonnée HTML — **non visible à la lecture** |
| `body.html.comment` | Commentaire HTML — **non visible à la lecture** |
| `body.html.style` | CSS (`background-image`, `@import`) |
| `body.html.other` | Autre balise du source |
| `attachment.name` | Nom de pièce jointe |

Les origines `meta`, `comment`, `style` et `other` méritent une attention particulière :
elles désignent des valeurs que **le destinataire ne peut pas voir**. C'est typiquement là
que se trouve l'URL de la landing page d'une campagne, publiée en `og:url` sans jamais
apparaître dans le message rendu.

Un IOC porte aussi un `snippet` — l'extrait du source qui l'entoure — et le mode `--all`
écrit `corps_html_source.txt` pour vérifier soi-même. Le rapport HTML expose la même source
dans un bloc repliable.

### Actionnabilité (`to_ids`)

Le drapeau `to_ids` de MISP répond à « peut-on brancher cet IOC sur une détection ? ».
Rien n'est supprimé : le non-actionnable est conservé avec son motif dans `reason`, mais
masqué par défaut dans les rendus et **exclu de `iocs.txt`**.

| Motif | Cas |
|---|---|
| `RFC1918/locale - infrastructure de transit` | IP privée d'un relais interne |
| `plage reservee - non routable` | IP réservée, multicast |
| `namespace XML/DTD - pas un IOC` | `www.w3.org`, `schemas.microsoft.com`… |
| `destinataire (victime) - ne pas bloquer` | adresse `To`/`Cc` |
| `identifiant unique du message - non bloquant` | `Message-ID` |

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

> **Format v2** — depuis l'ajout de la contextualisation, les entrées de `iocs` sont des
> objets et non plus des chaînes. Un `jq -r '.iocs.urls[]'` devient
> `jq -r '.iocs.urls[].value'`. Le champ `schema_version` permet de s'en assurer.

```jsonc
{
  "schema_version": 2,
  "file": "suspect.eml",
  "file_hashes":  { "md5": "...", "sha1": "...", "sha256": "...", "size": 12345 },
  "subject": "...", "date": "...",
  "sender_display": "...", "from": "...", "reply_to": "...", "return_path": "...",
  "to": "...", "cc": "...", "message_id": "...",
  "auth_results": { "spf": "...", "dkim": "pass", "dmarc": "pass",
                    "spf_client_ip": "203.0.113.9", "spf_result": "Fail",
                    "received_path": [] },
  "iocs": {
    "urls": [ {
      "value":       "http://phish.example/login",  // brut, pour le SIEM
      "display":     "hxxp://phish.example/login",  // défangé, pour l'affichage
      "type":        "url",                         // type MISP
      "category":    "Payload delivery",            // catégorie MISP
      "origins":     ["body.html.href"],            // provenance dans le message
      "context":     "Lien cliquable dans le corps HTML",
      "snippet":     "...<a href=\"hxxp://phish.example/login\">Cliquez ici</a>...",
      "to_ids":      true,                          // actionnable en détection
      "reason":      null,                          // motif si to_ids = false
      "occurrences": 2
    } ],
    "ips": [], "emails": []
  },
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
