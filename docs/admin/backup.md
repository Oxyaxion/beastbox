# Back up and restore

What to back up:
- **the user datasets**, with their **extended attributes**: they carry each file's identity (share links, tags, favorites,
  trash);
- **`state_dir`** (`/var/db/beastbox`): `app.db` (accounts, links) and `keys/`. **Always together, from the same date**: a lost
  key logs out every device and breaks every link.
- **A copy of `state_dir` gives access to every active public link** (their addresses are derived from `keys/` and
  `app.db`): only keep it encrypted (restic is), never in the clear in a ticket, a share or on a USB stick.
- `keys/<tenant>.links.key` only derives the public links. If a copy leaked: server stopped, delete this file, start:
  every link given out stops working, nobody is logged out. The “Links” pages still list them, with addresses that
  no longer work: revoke them and create new ones.

Run `beastbox manifest` before every backup (see "Manifest" below).

After any data restore, **server stopped until `rescan` is done** (`rescan` works on the files, without the server):
```sh
service beastbox stop
# restore the files (and .beastbox-manifest, for a file copy)
beastbox rescan --tenant T --user U
beastbox verify --tenant T --user U     # exit code 0 = no discrepancy
service beastbox start
```
- Started before `rescan`: clients re-download everything, and conflicts or lost links are possible.
- Files changed after the backup go back to their backed up version on the clients (conflict if changed locally).

## ZFS snapshot
```sh
service beastbox stop
zfs rollback zroot/beastbox/alpha/alice@before
beastbox rescan --tenant alpha --user alice && service beastbox start
```

## restic
From a snapshot, backing up the snapshot folder (not `backup .` from inside it):
```sh
zfs snapshot zroot/beastbox/alpha/alice@restic
( cd /mnt/data/beastbox-alpha/alice/.zfs/snapshot && restic -r <repo> backup --tag alice restic )
zfs destroy zroot/beastbox/alpha/alice@restic
sqlite3 /var/db/beastbox/app.db ".backup /var/db/beastbox/app.db.restic"
restic -r <repo> backup --tag state /var/db/beastbox/app.db.restic /var/db/beastbox/keys
```
Restore (server stopped, empty dataset, owner `beastbox`, `chmod 700`):
```sh
restic -r <repo> restore "latest:restic" --tag alice --target /mnt/data/beastbox-alpha/alice
beastbox rescan --tenant alpha --user alice && beastbox verify --tenant alpha --user alice
```
`state_dir`: put back `app.db` (from `app.db.restic`) and `keys/` from the same backup, then start (after `rescan`).
Limit: the user's root gets a new identity (a link to their **whole** space is lost, not the others).

## Manifest: before every backup
```sh
beastbox manifest --tenant T          # writes <dataset>/.beastbox-manifest, which leaves with the backup
```
- A catalogue of what the extended attributes hold (identity, tags, favorite, trash, SHA-1, time), not a database: the
  server never reads it, only `rescan` does, at restore. Cost: metadata only, ~1 s per 100,000 files.
- Needed when the backup loses the xattrs: rclone or any sync to S3, B2, pCloud, FTP; `cp`; `rsync` without `-X`.
  Harmless otherwise (ZFS, restic, bsdtar, `rsync -X` keep them).
- Without it, after such a restore: clients re-download everything, local changes become conflicts, links, tags and
  favorites are lost (tried for real: `../dev/CLIENTS.md`).

Restore from such a copy: server stopped, copy back **with** the manifest, `rescan`, start.
- `rescan` rereads the files to prove their content (SHA-1): one read of the restored data, 8 files at once
  (`--readers N`, 1 to 8).
- Never `rescan` before the manifest is back: everything gets new identities, and a link opened then is ended for good.

## Restore one file or folder (version of a past day)
`beastbox restore --tenant T --user U --from DIR --path P [--to Q]`: copies `P` of `DIR` into the user's space. Default
target: `P` if it no longer exists, otherwise `P (restored YYYY-MM-DD)`. Never overwrites (an existing target is refused);
the copy is a new file (no tags or links); the server can stay started, no `rescan` needed.
```sh
S=/mnt/data/beastbox-alpha/alice/.zfs/snapshot/daily-2026-11-07     # from the host first: ls "$S" (a jail cannot mount it)

# A file changed since: the old version comes next to it → Docs/contrat (restored 2026-11-17).pdf
beastbox restore --tenant alpha --user alice --from "$S" --path Docs/contrat.pdf
# A folder deleted since: back at its place → Photos/2026
beastbox restore --tenant alpha --user alice --from "$S" --path Photos/2026
# A chosen name, in a folder created if needed → Archives/contrat J-10.pdf
beastbox restore --tenant alpha --user alice --from "$S" --path Docs/contrat.pdf --to "Archives/contrat J-10.pdf"

# From an external backup: restore it into a work folder first, then the same command
restic -r <repo> restore latest --tag alice --include /Docs/contrat.pdf --target /var/tmp/r
rclone copy <remote>:alice/Docs/contrat.pdf /var/tmp/r/Docs/
beastbox restore --tenant alpha --user alice --from /var/tmp/r --path Docs/contrat.pdf
```
- `--from` is any folder, also files never seen before (an import): its origin is not checked.
- Names in any script are kept (accents decomposed by a Mac come back composed). Links, special files and names not
  allowed are passed over and counted in the report.
- The name of `--path` itself must already be composed: an item whose own name a Mac decomposed is restored by giving its
  parent folder instead (its children are read as they are).
- Failure midway (quota, unreadable file): the partial copy goes to the user's trash.

## Jail export
`bastille stop`, `bastille export --tgz <jail>`: full archive (mounted data included). Restore: `bastille import <archive>`.
Unmount the data datasets before destroying or replacing the jail.

## Pitfalls
- `mv` between datasets loses the xattrs, like a copy.
- Files changed directly on disk: run `beastbox rescan` afterwards.
