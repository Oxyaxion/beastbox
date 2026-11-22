//! UI language: English by default, French if the browser asks for it or the user chose it.
//!
//! Templates and messages are written in English; `Lang::t` gives the French text. An unknown or
//! untranslated string falls back to the English one, so a missing entry is never a blank page.

use axum::http::{HeaderMap, header};

/// Cookie holding the choice made in the account page (a year, per browser).
pub const COOKIE: &str = "lang";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Fr,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Fr => "fr",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Fr => "Français",
        }
    }

    /// Language of the request: the account cookie, then `Accept-Language`, then English.
    pub fn from(h: &HeaderMap, cookie: Option<&str>) -> Self {
        cookie
            .and_then(Self::from_code)
            .or_else(|| {
                h.get(header::ACCEPT_LANGUAGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(Self::from_accept)
            })
            .unwrap_or(Lang::En)
    }

    fn from_code(s: &str) -> Option<Self> {
        match s.get(..2)?.to_ascii_lowercase().as_str() {
            "en" => Some(Lang::En),
            "fr" => Some(Lang::Fr),
            _ => None,
        }
    }

    /// Best supported tag of an `Accept-Language` header (`fr-CH,fr;q=0.9,en;q=0.8`).
    fn from_accept(v: &str) -> Option<Self> {
        v.split(',')
            .filter_map(|part| {
                let mut it = part.trim().split(';');
                let tag = it.next()?.trim().to_ascii_lowercase();
                let q = it
                    .find_map(|p| p.trim().strip_prefix("q="))
                    .and_then(|q| q.parse::<f32>().ok())
                    .unwrap_or(1.0);
                let lang = match tag.split(['-', '_']).next()? {
                    "en" => Lang::En,
                    "fr" => Lang::Fr,
                    _ => return None,
                };
                Some((q, lang))
            })
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, l)| l)
    }

    /// Text in this language; `en` is also the key of the French table.
    pub fn t(self, en: &'static str) -> &'static str {
        if self == Lang::En {
            return en;
        }
        FR.iter().find(|(k, _)| *k == en).map_or(en, |(_, fr)| *fr)
    }
}

/// French texts, keyed by their English text (checked by the test at the bottom).
const FR: &[(&str, &str)] = &[
    ("From:", "Depuis :"),
    ("Copy link", "Copier le lien"),
    ("Show the link", "Afficher le lien"),
    ("Show the link to", "Afficher le lien vers"),
    ("downloads", "téléchargements"),
    ("Last access:", "Dernier accès :"),
    ("Link:", "Lien :"),
    ("Show every link", "Afficher tous les liens"),
    (
        "1 to 32 letters, digits, spaces, - or _.",
        "1 à 32 lettres, chiffres, espaces, - ou _.",
    ),
    ("characters at least", "caractères au moins"),
    (
        "characters at least, without your name, a sequence or a keyboard row",
        "caractères au moins, sans votre nom, ni suite, ni rangée du clavier",
    ),
    ("Choose your password", "Choisissez votre mot de passe"),
    ("Two-step verification", "Validation en deux étapes"),
    ("Continue", "Continuer"),
    (
        "Few recovery codes left: create new ones.",
        "Il reste peu de codes de secours : créez-en de nouveaux.",
    ),
    (
        "New recovery codes: the old ones no longer work.",
        "Nouveaux codes de secours : les anciens ne fonctionnent plus.",
    ),
    (
        "Set up two-step verification in the web interface first, then connect this device again.",
        "Configurez d'abord la validation en deux étapes dans l'interface web, puis reconnectez cet appareil.",
    ),
    (
        "Two-step verification is already on.",
        "La validation en deux étapes est déjà activée.",
    ),
    (
        "Two-step verification is not offered in this space.",
        "La validation en deux étapes n'est pas proposée dans cet espace.",
    ),
    (
        "Two-step verification is off.",
        "La validation en deux étapes est désactivée.",
    ),
    (
        "Two-step verification is on.",
        "La validation en deux étapes est activée.",
    ),
    (
        "Wrong code: check that the phone is on time and try again.",
        "Code incorrect : vérifiez que le téléphone est à l'heure et réessayez.",
    ),
    (
        "Wrong code: nothing was changed.",
        "Code incorrect : rien n'a été changé.",
    ),
    ("Wrong or already used code.", "Code incorrect ou déjà utilisé."),
    (
        "Wrong password: nothing was changed.",
        "Mot de passe incorrect : rien n'a été changé.",
    ),
    (
        "Wrong, missing or already used code.",
        "Code incorrect, absent ou déjà utilisé.",
    ),
    (
        "After the password, a code from an app on your phone is asked at each sign-in, and to connect a new device. Devices already connected stay connected.",
        "Après le mot de passe, un code donné par une application de votre téléphone est demandé à chaque connexion, et pour connecter un nouvel appareil. Les appareils déjà connectés le restent.",
    ),
    ("Turn on two-step verification", "Activer la validation en deux étapes"),
    (
        "Open an authenticator app on your phone (Aegis, FreeOTP, Google Authenticator…) and add an account.",
        "Ouvrez une application d'authentification sur votre téléphone (Aegis, FreeOTP, Google Authenticator…) et ajoutez un compte.",
    ),
    (
        "Scan this code, or type this key:",
        "Scannez ce code, ou saisissez cette clé :",
    ),
    (
        "Enter the 6-digit code the app shows.",
        "Saisissez le code à 6 chiffres affiché par l'application.",
    ),
    ("Code", "Code"),
    ("On.", "Activée."),
    ("recovery codes left.", "codes de secours restants."),
    (
        "Keep these recovery codes somewhere safe (printed, password manager): each one signs you in once without your phone. They will not be shown again.",
        "Gardez ces codes de secours en lieu sûr (imprimés, gestionnaire de mots de passe) : chacun permet une connexion sans votre téléphone. Ils ne seront plus affichés.",
    ),
    (
        "New recovery codes or turn off",
        "Nouveaux codes de secours ou désactivation",
    ),
    ("Code from the app", "Code de l'application"),
    ("New recovery codes", "Nouveaux codes de secours"),
    (
        "Required for this space by the administrator: it cannot be turned off.",
        "Imposée pour cet espace par l'administrateur : elle ne peut pas être désactivée.",
    ),
    ("Turn off", "Désactiver"),
    (
        "Enter the 6-digit code shown by the authenticator app on your phone.",
        "Saisissez le code à 6 chiffres affiché par l'application d'authentification de votre téléphone.",
    ),
    ("No phone at hand?", "Pas de téléphone sous la main ?"),
    ("Recovery code", "Code de secours"),
    ("Sign in with a recovery code", "Se connecter avec un code de secours"),
    (
        "This space requires a code from an app on your phone at each sign-in. Set it up once to continue.",
        "Cet espace demande à chaque connexion un code donné par une application de votre téléphone. Configurez-la une fois pour continuer.",
    ),
    ("Welcome", "Bienvenue"),
    (
        "The password you received was set by the administrator: replace it with your own to continue.",
        "Le mot de passe reçu a été fixé par l'administrateur : remplacez-le par le vôtre pour continuer.",
    ),
    ("Password received", "Mot de passe reçu"),
    ("New password again", "Nouveau mot de passe, à nouveau"),
    ("Save and continue", "Enregistrer et continuer"),
    (
        "The two new passwords differ: nothing was changed.",
        "Les deux nouveaux mots de passe diffèrent : rien n'a été changé.",
    ),
    ("Password chosen", "Mot de passe choisi"),
    (
        "Sign in again with your new password.",
        "Reconnectez-vous avec votre nouveau mot de passe.",
    ),
    (
        "Choose your password in the web interface first, then connect this device again.",
        "Choisissez d'abord votre mot de passe dans l'interface web, puis reconnectez cet appareil.",
    ),
    ("20 tags at most per item.", "20 tags au plus par élément."),
    (
        "A client requests access to your files.",
        "Un client demande l'accès à vos fichiers.",
    ),
    (
        "Access refused: wrong password",
        "Accès refusé : mot de passe incorrect",
    ),
    ("Account", "Compte"),
    ("Actions", "Actions"),
    (
        "Add another software (rclone, WebDAV)",
        "Ajouter un autre logiciel (rclone, WebDAV)",
    ),
    ("Administrator", "Administrateur"),
    (
        "Anyone with a link can open it without an account. Revoking cuts access immediately.",
        "Toute personne qui a un lien y accède sans compte. Révoquer coupe l'accès tout de suite.",
    ),
    ("App password created.", "Mot de passe d'application créé."),
    ("App password not found.", "Mot de passe d'application introuvable."),
    ("App password revoked.", "Mot de passe d'application révoqué."),
    ("Appearance", "Apparence"),
    ("Authorize this client", "Autoriser ce client"),
    ("Back", "Retour"),
    (
        "Beyond 4 GiB or 65,535 items: use a sync client.",
        "Au-delà de 4 Gio ou de 65 535 éléments : utilisez un client de synchronisation.",
    ),
    ("Breadcrumb", "Fil d'Ariane"),
    ("Cancel", "Annuler"),
    (
        "Cannot change it right now: nothing was changed.",
        "Changement impossible pour l'instant : rien n'a été changé.",
    ),
    ("Change the password", "Modifier le mot de passe"),
    ("Choose files", "Choisir des fichiers"),
    (
        "Choose the destination folder.",
        "Choisissez le dossier de destination.",
    ),
    (
        "Choosing a theme and a mode requires JavaScript.",
        "Le choix du thème et du mode demande JavaScript.",
    ),
    (
        "Click the star in a listing, or add it from the “Tags and sharing” page.",
        "Cliquez sur l'étoile dans une liste, ou ajoutez-le depuis la page « Tags et partage ».",
    ),
    ("Client connected", "Client connecté"),
    ("Close", "Fermer"),
    ("Close preview", "Fermer l'aperçu"),
    ("Confirm", "Valider"),
    ("Confirmation required", "Confirmation requise"),
    ("Connect a client", "Connecter un client"),
    ("Connected devices", "Appareils connectés"),
    ("Connected on", "Connecté le"),
    (
        "Copy this password into your software now. It will not be shown again.",
        "Copiez ce mot de passe dans votre logiciel maintenant. Il ne sera plus affiché.",
    ),
    ("Create the password", "Créer le mot de passe"),
    ("Current password", "Mot de passe actuel"),
    ("Dark", "Sombre"),
    ("Delete", "Supprimer"),
    ("Delete permanently", "Supprimer définitivement"),
    ("Deleted items stay here", "Les éléments supprimés restent ici"),
    ("Details of", "Détails de"),
    ("Details, tags and sharing", "Détails, tags et partage"),
    ("Download", "Télécharger"),
    ("Download all", "Tout télécharger"),
    ("Download all (ZIP)", "Tout télécharger (ZIP)"),
    (
        "Links created and revoked, downloads and drops by people who have a link, and refused passwords. Kept",
        "Liens créés et révoqués, téléchargements et dépôts faits par les personnes qui ont un lien, et mots de passe refusés. Conservés",
    ),
    (
        "Drop files or folders here to upload them. To move an item, drag it onto a folder.",
        "Déposez ici des fichiers ou des dossiers à envoyer. Pour déplacer un élément, glissez-le sur un dossier.",
    ),
    (
        "Only public links are offered.",
        "Seuls les liens publics sont proposés.",
    ),
    (
        "Only read-only, read-and-upload and drop-only links are offered.",
        "Seuls les liens en lecture seule, en lecture et envoi, et en dépôt seul sont proposés.",
    ),
    (
        "Drop and upload only apply to a folder.",
        "Le dépôt et l'envoi ne s'appliquent qu'à un dossier.",
    ),
    (
        "Browse, download and add files",
        "Parcourir, télécharger et ajouter des fichiers",
    ),
    (
        "Let visitors send files…",
        "Laisser les visiteurs envoyer des fichiers…",
    ),
    (
        "Anyone with the link will be able to put files into this folder. Preferably add a password and an expiry date.",
        "Toute personne qui a le lien pourra déposer des fichiers dans ce dossier. Ajoutez de préférence un mot de passe et une date d'expiration.",
    ),
    (
        "They see the folder and can send files into it, without changing or deleting anything.",
        "Il voit le dossier et peut y envoyer des fichiers, sans rien modifier ni supprimer.",
    ),
    ("Label", "Libellé"),
    ("For you, to recognize the link", "Pour vous, pour reconnaître le lien"),
    ("Note to the guest", "Note au destinataire"),
    (
        "Shown at the top of the link's page",
        "Affichée en haut de la page du lien",
    ),
    ("Hide the download", "Masquer le téléchargement"),
    (
        "Images, PDF and text open in the browser; no download button nor archive. A determined guest can still save what they see.",
        "Images, PDF et textes s'ouvrent dans le navigateur ; ni bouton de téléchargement ni archive. Un invité déterminé peut quand même enregistrer ce qu'il voit.",
    ),
    ("read and upload", "lecture et envoi"),
    ("Add files", "Ajouter des fichiers"),
    (
        "Connect the mobile app (QR code)",
        "Connecter l'application mobile (QR code)",
    ),
    (
        "In the Nextcloud app on the phone, on the login screen, choose “Scan QR code”: the phone connects without typing a password.",
        "Dans l'application Nextcloud du téléphone, à l'écran de connexion, choisissez « Scanner un QR code » : le téléphone se connecte sans saisir de mot de passe.",
    ),
    ("Show the QR code", "Afficher le QR code"),
    (
        "Open the Nextcloud app on the phone.",
        "Ouvrez l'application Nextcloud sur le téléphone.",
    ),
    (
        "On the login screen, choose “Scan QR code”.",
        "À l'écran de connexion, choisissez « Scanner un QR code ».",
    ),
    (
        "Aim at this code: the phone connects and shows up in the list above.",
        "Visez ce code : le téléphone se connecte et apparaît dans la liste ci-dessus.",
    ),
    (
        "This code gives access to your files: show it to nobody. It stops working after 10 minutes if unused, and will not be shown again.",
        "Ce code donne accès à vos fichiers : ne le montrez à personne. Il n'est plus valable après 10 minutes s'il n'a pas servi, et ne sera plus affiché.",
    ),
    ("Login QR code", "QR code de connexion"),
    ("Mobile app (QR code)", "Application mobile (QR code)"),
    ("Done", "C'est fait"),
    ("Item not found", "Élément introuvable"),
    (
        "This file or folder no longer exists, or it was moved outside your space.",
        "Ce fichier ou ce dossier n'existe plus, ou il a été déplacé hors de votre espace.",
    ),
    ("Link revoked", "Lien révoqué"),
    ("Open in the browser", "Ouvrir dans le navigateur"),
    (
        "The files you send are added to this folder; nothing already there is replaced.",
        "Les fichiers envoyés sont ajoutés à ce dossier ; rien de ce qui s'y trouve n'est remplacé.",
    ),
    ("view only", "consultation seule"),
    (
        "Invalid characters in the label or the note.",
        "Caractères invalides dans le libellé ou la note.",
    ),
    (
        "Label too long (100 characters at most).",
        "Libellé trop long (100 caractères au plus).",
    ),
    (
        "Note too long (1,000 characters at most).",
        "Note trop longue (1 000 caractères au plus).",
    ),
    (
        "Each device has its own app password. Revoking one disconnects only that device; it will have to reconnect.",
        "Chaque appareil a son propre mot de passe d'application. Révoquer en déconnecte un seul ; il faudra le reconnecter.",
    ),
    ("Empty the trash", "Vider la corbeille"),
    (
        "Empty the trash? The items will be permanently deleted.",
        "Vider la corbeille ? Les éléments seront supprimés définitivement.",
    ),
    ("Error", "Erreur"),
    ("Star", "Favori"),
    ("Starred", "Favoris"),
    ("File name, or tag:invoice", "Nom de fichier, ou tag:facture"),
    ("Files", "Fichiers"),
    ("First", "Les"),
    ("Folder", "Dossier"),
    ("Folder contents", "Contenu du dossier"),
    ("Folder too large", "Dossier trop volumineux"),
    ("Follow the system", "Comme le système"),
    ("Full link history", "Tout l'historique des liens"),
    ("Graphite (always dark)", "Graphite (toujours sombre)"),
    ("Green", "Vert"),
    ("Grid", "Grille"),
    ("History", "Historique"),
    ("History pages", "Pages de l'historique"),
    ("I confirm", "Je confirme"),
    (
        "Invalid form token: reload the page.",
        "Jeton de formulaire invalide : rechargez la page.",
    ),
    ("Invalid number of downloads.", "Nombre de téléchargements invalides."),
    ("Invalid or past expiry date.", "Date d'expiration invalide ou passée."),
    (
        "Item without identity: run “beastbox rescan” first.",
        "Élément sans identité : lancer « beastbox rescan » d'abord.",
    ),
    ("Language", "Langue"),
    (
        "Language of the interface. Taken from the browser until you choose one.",
        "Langue de l'interface. Celle du navigateur tant que vous n'en choisissez pas une.",
    ),
    ("Last use", "Dernier usage"),
    ("Light", "Clair"),
    ("Link created", "Lien créé"),
    ("downloads at most", "téléchargements au plus"),
    (
        "Send this link to the people concerned. It is also marked “New” in the list below.",
        "Envoyez ce lien aux personnes concernées. Il est aussi marqué « Nouveau » dans la liste ci-dessous.",
    ),
    ("Back to", "Retour à"),
    ("New", "Nouveau"),
    ("Link not found.", "Lien introuvable."),
    ("Link refused", "Lien refusé"),
    ("Link revoked.", "Lien révoqué."),
    ("Link unavailable", "Lien indisponible"),
    ("List", "Liste"),
    ("Main navigation", "Navigation principale"),
    ("Missing fields.", "Champs manquants."),
    ("Mode", "Mode"),
    ("Modified", "Modifié"),
    ("Move or copy", "Déplacer ou copier"),
    ("Move here", "Déplacer ici"),
    ("Copy here", "Copier ici"),
    ("Duplicate", "Dupliquer"),
    ("Move or copy to…", "Déplacer ou copier vers…"),
    ("Move or copy…", "Déplacer ou copier…"),
    ("Already in this folder", "Déjà dans ce dossier"),
    (
        "Choose another folder, or duplicate the selection.",
        "Choisissez un autre dossier, ou dupliquez la sélection.",
    ),
    (
        "Move the selection to the trash?",
        "Mettre la sélection à la corbeille ?",
    ),
    ("My files", "Mes fichiers"),
    ("Name", "Nom"),
    ("Navigation", "Navigation"),
    ("New password", "Nouveau mot de passe"),
    (
        "New password too short: nothing was changed.",
        "Nouveau mot de passe trop court : rien n'a été changé.",
    ),
    (
        "The new password must not contain the account or tenant name: nothing was changed.",
        "Le nouveau mot de passe ne doit contenir ni le nom du compte ni celui de l'espace : rien n'a été changé.",
    ),
    (
        "New password too easy to guess (repeated characters, sequence or keyboard row): nothing was changed.",
        "Nouveau mot de passe trop facile à deviner (caractères répétés, suite ou rangée du clavier) : rien n'a été changé.",
    ),
    (
        "The new password must differ from the current one: nothing was changed.",
        "Le nouveau mot de passe doit différer de l'actuel : rien n'a été changé.",
    ),
    ("Next page", "Page suivante"),
    (
        "No active links. Create one from the “Tags and sharing” page of a file or folder.",
        "Aucun lien actif. Créez-en un depuis la page « Tags et partage » d'un fichier ou d'un dossier.",
    ),
    (
        "No connected device. Open the Nextcloud client on your computer or phone and connect to this server.",
        "Aucun appareil connecté. Ouvrez le client Nextcloud sur votre ordinateur ou votre téléphone et connectez-vous à ce serveur.",
    ),
    ("No destination", "Aucune destination"),
    ("No starred folder", "Aucun dossier favori"),
    ("Nothing starred yet.", "Aucun favori pour l'instant."),
    ("No results for", "Aucun résultat pour"),
    ("No subfolder", "Aucun sous-dossier"),
    ("Not found", "Introuvable"),
    ("Nothing for this link.", "Rien pour ce lien."),
    ("Nothing selected", "Aucune sélection"),
    ("Nothing yet.", "Rien pour l'instant."),
    ("OK", "OK"),
    ("Open", "Accéder"),
    ("Open details", "Ouvrir les détails"),
    ("Or drop them here.", "Ou glissez-les ici."),
    ("Page", "Page"),
    ("Pages", "Pages"),
    ("Password", "Mot de passe"),
    (
        "Password changed. Use it the next time you sign in.",
        "Mot de passe changé. Utilisez-le à la prochaine connexion.",
    ),
    (
        "Password too short (8 characters at least).",
        "Mot de passe trop court (8 caractères au moins).",
    ),
    ("Permanently delete", "Supprimer définitivement"),
    ("Permanently deleted.", "Supprimé définitivement."),
    ("Preview", "Aperçu"),
    ("Preview of", "Aperçu de"),
    ("Previous page", "Page précédente"),
    ("Protected link", "Lien protégé"),
    ("Public link of", "Lien public de"),
    ("Recent activity", "Activité récente"),
    ("Recent files", "Fichiers récents"),
    ("Recently deleted", "Récemment supprimés"),
    ("Restore from the trash", "Restaurer depuis la corbeille"),
    ("Refused", "Refusé"),
    ("Remembered by this browser.", "Mémorisé par ce navigateur."),
    ("Rename", "Renommer"),
    ("Restore", "Restaurer"),
    ("Revoke", "Révoquer"),
    ("Revoke the link to", "Révoquer le lien de"),
    ("Save", "Enregistrer"),
    ("Edit", "Modifier"),
    ("File name", "Nom du fichier"),
    (
        "This file has a share link: renaming it ends the link.",
        "Ce fichier a un lien de partage : le renommer met fin au lien.",
    ),
    (
        "A name, without “/”: the file stays in its folder.",
        "Un nom, sans « / » : le fichier reste dans son dossier.",
    ),
    (
        "Keep the name of a text file: .txt, .md, .json, .sh, .yaml, .csv…",
        "Gardez un nom de fichier texte : .txt, .md, .json, .sh, .yaml, .csv…",
    ),
    ("This name is not allowed.", "Ce nom n'est pas autorisé."),
    (
        "Saved, but not renamed: an item with this name already exists in this folder.",
        "Enregistré, mais pas renommé : un élément porte déjà ce nom dans ce dossier.",
    ),
    (
        "Saved, but not renamed: the server is read-only for now.",
        "Enregistré, mais pas renommé : le serveur est en lecture seule pour le moment.",
    ),
    (
        "Saved, but not renamed: the operation could not be completed.",
        "Enregistré, mais pas renommé : l'opération n'a pas pu aboutir.",
    ),
    ("Text file", "Fichier texte"),
    ("File not created", "Fichier non créé"),
    (
        "Choose the name of a text file: .txt, .md, .json, .sh, .yaml, .csv…",
        "Choisissez le nom d'un fichier texte : .txt, .md, .json, .sh, .yaml, .csv…",
    ),
    (
        "An item with this name already exists in this folder.",
        "Un élément porte déjà ce nom dans ce dossier.",
    ),
    (
        "This folder does not exist (any more).",
        "Ce dossier n'existe pas (ou plus).",
    ),
    ("Copied", "Copié"),
    ("Copy failed", "Échec de la copie"),
    ("Copy the contents", "Copier le contenu"),
    ("Copy the contents of", "Copier le contenu de"),
    ("Not saved", "Non enregistré"),
    (
        "Not enough space left (quota or disk).",
        "Plus assez d'espace (quota ou disque).",
    ),
    (
        "The server is read-only for now.",
        "Le serveur est en lecture seule pour le moment.",
    ),
    ("Preview — not saved yet", "Aperçu — pas encore enregistré"),
    ("Cannot edit this file", "Impossible de modifier ce fichier"),
    (
        "Only text files of 512 KiB at most, in UTF-8, can be edited here.",
        "Seuls les fichiers texte de 512 Kio au plus, en UTF-8, se modifient ici.",
    ),
    (
        "This file was changed elsewhere since you opened it",
        "Ce fichier a été modifié ailleurs depuis que vous l'avez ouvert",
    ),
    ("version of", "version du"),
    (
        "Your text is kept below; nothing has been saved.",
        "Votre texte est conservé ci-dessous ; rien n'a été enregistré.",
    ),
    ("Replace it with my text", "Le remplacer par mon texte"),
    (
        "Discard my changes and reload",
        "Abandonner mes modifications et recharger",
    ),
    ("Contents of", "Contenu de"),
    ("Ctrl+S saves.", "Ctrl+S enregistre."),
    ("512 KiB at most.", "512 Kio au plus."),
    ("Save the password", "Enregistrer le mot de passe"),
    ("Search", "Rechercher"),
    ("Search files", "Rechercher des fichiers"),
    ("Select", "Sélectionner"),
    ("Select all", "Tout sélectionner"),
    ("Selection", "Sélection"),
    ("Shared links", "Liens partagés"),
    ("Show", "Afficher"),
    ("Sort", "Trier"),
    ("Sort:", "Trier :"),
    ("Type", "Type"),
    ("Ascending", "Croissant"),
    ("Descending", "Décroissant"),
    ("Sign in", "Connexion"),
    (
        "Sign in with single sign-on",
        "Se connecter avec l'authentification unique",
    ),
    (
        "This server signs in through its identity provider.",
        "Ce serveur se connecte via son fournisseur d'identité.",
    ),
    ("Sign out", "Déconnexion"),
    ("Size", "Taille"),
    ("Software name", "Nom du logiciel"),
    ("Tag refused", "Tag refusé"),
    ("Tags", "Tags"),
    ("Tags and sharing", "Tags et partage"),
    (
        "The files you send are passed on to their recipient.",
        "Les fichiers envoyés sont transmis à leur destinataire.",
    ),
    (
        "The operation could not be completed.",
        "L'opération n'a pas pu aboutir.",
    ),
    (
        "The person who sent you this link protected it with a password.",
        "La personne qui vous a envoyé ce lien l'a protégé par un mot de passe.",
    ),
    (
        "The trash holds too many items to show them all; “Empty the trash” deletes them all.",
        "La corbeille contient trop d'éléments pour être affichée en entier ; « Vider la corbeille » les supprime tous.",
    ),
    ("The trash is empty.", "La corbeille est vide."),
    ("Theme", "Thème"),
    (
        "This folder holds too many items: only the first 10,000 are taken into account (use a sync client).",
        "Ce dossier contient trop d'éléments : seuls les 10 000 premiers sont pris en compte (utilisez un client de synchronisation).",
    ),
    ("This folder is empty.", "Ce dossier est vide."),
    (
        "This folder is empty. Drop files here, or create a folder.",
        "Ce dossier est vide. Déposez des fichiers ici, ou créez un dossier.",
    ),
    (
        "This item does not exist or is no longer accessible.",
        "Cet élément n'existe pas ou n'est plus accessible.",
    ),
    (
        "This item is no longer in the trash.",
        "Cet élément n'est plus dans la corbeille.",
    ),
    (
        "This link does not exist or is no longer valid.",
        "Ce lien n'existe pas ou n'est plus valide.",
    ),
    ("This theme has a fixed mode. ", "Ce thème a un mode fixe. "),
    ("Tick at least one item.", "Cochez au moins un élément."),
    (
        "Tick “I confirm” to delete permanently.",
        "Cochez « Je confirme » pour supprimer définitivement.",
    ),
    ("Today", "Aujourd'hui"),
    ("Too many tags", "Trop de tags"),
    ("Trash", "Corbeille"),
    ("Trash emptied.", "Corbeille vidée."),
    ("Unknown action", "Action inconnue"),
    ("Unknown or expired login link.", "Lien de connexion inconnu ou expiré."),
    ("Unselect all", "Tout désélectionner"),
    ("Upload a folder", "Envoyer un dossier"),
    ("Upload files", "Envoyer des fichiers"),
    ("Uploading requires JavaScript.", "Le dépôt demande JavaScript."),
    (
        "Used for the web interface and to connect new devices. Devices already connected stay connected.",
        "Sert à l'interface web et à la connexion des nouveaux appareils. Les appareils déjà connectés le restent.",
    ),
    ("Used space", "Espace utilisé"),
    ("User", "Utilisateur"),
    ("Username", "Utilisateur"),
    ("View", "Affichage"),
    ("White (always light)", "Blanc (toujours clair)"),
    (
        "Without JavaScript: navigation, download, move and bulk delete; uploading requires JavaScript.",
        "Sans JavaScript : navigation, téléchargement, déplacement et suppression groupés ; l'envoi demande JavaScript.",
    ),
    (
        "Wrong current password: nothing was changed.",
        "Mot de passe actuel incorrect : rien n'a été changé.",
    ),
    ("Wrong password.", "Mot de passe incorrect."),
    ("Wrong username or password.", "Identifiants incorrects."),
    ("Yesterday", "Hier"),
    ("You can close this page.", "Vous pouvez fermer cette page."),
    ("Your shared links", "Vos liens partagés"),
    (
        "Your space is larger than the index: some files are missing.",
        "Votre espace dépasse la taille de l'index : certains fichiers n'apparaissent pas.",
    ),
    ("days", "jours"),
    (
        "days, even after the link is revoked.",
        "jours, même après la révocation du lien.",
    ),
    ("deleted on", "supprimé le"),
    ("deleted or moved target", "source supprimée ou déplacée"),
    ("downloaded", "téléchargé"),
    ("downloaded as a ZIP archive", "téléchargé en archive ZIP"),
    ("drop only", "dépôt seul"),
    ("exhausted", "épuisé"),
    ("expired", "expiré"),
    ("starred items", "premiers favoris"),
    ("Filters", "Filtres"),
    ("In", "Dans"),
    ("Search everywhere", "Chercher partout"),
    ("Folders", "Dossiers"),
    ("Images", "Images"),
    ("Videos", "Vidéos"),
    ("Audio", "Audio"),
    ("PDF", "PDF"),
    ("Documents", "Documents"),
    ("Last 7 days", "7 derniers jours"),
    ("Last 30 days", "30 derniers jours"),
    ("This year", "Cette année"),
    ("Wildcards (whole name):", "Jokers (nom entier) :"),
    ("Text size", "Taille du texte"),
    ("Menu", "Menu"),
    ("Normal", "Normale"),
    ("Large", "Grande"),
    ("Larger", "Très grande"),
    (
        "Every word must appear in the name, accents and case ignored. Filters:",
        "Chaque mot doit figurer dans le nom, sans tenir compte des accents ni des majuscules. Filtres :",
    ),
    (
        "free. The trash counts towards used space.",
        "libres. La corbeille compte dans l'espace utilisé.",
    ),
    ("from", "de"),
    ("in", "dans"),
    ("item", "élément"),
    ("modified on", "modifié le"),
    ("never", "jamais"),
    ("of", "sur"),
    ("per page", "par page"),
    ("rclone on the NAS", "rclone sur le NAS"),
    ("read only", "lecture seule"),
    ("result", "résultat"),
    (
        "results (refine the search)",
        "premiers résultats (précisez la recherche)",
    ),
    ("revoked", "révoqué"),
    ("shared link", "lien partagé"),
    ("suspended: in the trash", "suspendu : à la corbeille"),
    (
        "then are permanently deleted. They count towards your space.",
        "puis sont supprimés définitivement. Ils comptent dans votre espace.",
    ),
    ("until you empty the trash", "jusqu'à ce que vous vidiez la corbeille"),
    ("used out of", "utilisés sur"),
    ("8 characters at least", "8 caractères au moins"),
    ("Add", "Ajouter"),
    ("Add a star", "Ajouter aux favoris"),
    ("All items with this tag", "Tous les éléments avec ce tag"),
    (
        "Anyone with the link can open it, without an account.",
        "Toute personne qui a le lien y accède, sans compte.",
    ),
    ("Browse and download", "Consulter et télécharger"),
    ("Create the link", "Créer le lien"),
    ("Download (ZIP)", "Télécharger (ZIP)"),
    ("Downloads at most", "Téléchargements au plus"),
    ("Drop files only", "Déposer des fichiers seulement"),
    (
        "1 = single use; empty = no limit",
        "1 = usage unique ; vide = sans limite",
    ),
    ("Expires on", "Expire le"),
    ("Gallery", "Galerie"),
    ("Included; empty = never", "Inclus ; vide = jamais"),
    ("Keyboard: ← and →", "Touches ← et → du clavier"),
    (
        "Keywords to find this item again.",
        "Des mots-clés pour retrouver cet élément.",
    ),
    ("New tag", "Nouveau tag"),
    ("Next image", "Image suivante"),
    ("No tag yet.", "Aucun tag pour l'instant."),
    ("Open folder", "Ouvrir le dossier"),
    ("Previous image", "Image précédente"),
    (
        "Options (password, expiry, limit, label, note)",
        "Options (mot de passe, expiration, limite, libellé, note)",
    ),
    ("Remove", "Retirer"),
    ("Remove the tag", "Retirer le tag"),
    ("See my shared links", "Voir mes liens partagés"),
    ("Share by link", "Partager par lien"),
    (
        "They see and download the file, without changing it.",
        "Il voit et télécharge le fichier, sans le modifier.",
    ),
    (
        "They see the folder contents, without changing anything.",
        "Il voit le contenu du dossier, sans rien modifier.",
    ),
    (
        "They send files without seeing the folder contents.",
        "Il envoie des fichiers sans voir le contenu du dossier.",
    ),
    ("What the guest may do", "Ce que l'invité peut faire"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn detection() {
        let h = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_str(v).unwrap());
            h
        };
        assert_eq!(Lang::from(&h("fr-CH,fr;q=0.9,en;q=0.8"), None), Lang::Fr);
        assert_eq!(Lang::from(&h("fr;q=0.5,en;q=0.9"), None), Lang::En);
        assert_eq!(Lang::from(&h("en-GB,en;q=0.9"), None), Lang::En);
        assert_eq!(Lang::from(&h("de-DE,de;q=0.9"), None), Lang::En);
        assert_eq!(Lang::from(&HeaderMap::new(), None), Lang::En);
        // The account choice wins over the browser.
        assert_eq!(Lang::from(&h("fr"), Some("en")), Lang::En);
        assert_eq!(Lang::from(&h("en"), Some("fr")), Lang::Fr);
    }

    /// Every string used in a template or in the code has a French entry.
    #[test]
    fn every_used_string_is_translated() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut stack = vec![src.join("templates"), src.join("src")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if !p.extension().is_some_and(|x| x == "html" || x == "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                for key in keys(&text) {
                    assert!(
                        FR.iter().any(|(k, _)| *k == key),
                        "no French text for {key:?} (in {})",
                        p.display()
                    );
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (k, _) in FR {
            assert!(seen.insert(*k), "duplicate French entry for {k:?}");
        }
    }

    /// String literals passed to `.t(`.
    fn keys(text: &str) -> Vec<&str> {
        let mut v = Vec::new();
        for (i, _) in text.match_indices(".t(\"") {
            let rest = &text[i + 4..];
            if let Some(end) = rest.find('"') {
                v.push(&rest[..end]);
            }
        }
        v
    }
}
