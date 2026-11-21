# What real clients ask for

Source (J1, 2026-11-14): reverse proxy access logs of a Nextcloud 35 instance in production (method, path, response code
only: no headers or bodies). Clients: desktop `mirall/34.0.4` and `34.0.5`, Android `35.0.2`.
**This is not the full session recording the plan asks for (§7)**: headers, PROPFIND bodies and the Login Flow are missing.

| Request | Client | Nextcloud response | Beastbox J1 |
|---|---|---|---|
| `PROPFIND /remote.php/dav/files/<u>/…` | desktop (heavy), android | 207 | 207 |
| `GET /remote.php/dav/files/<u>/…` | both | 200 | 200 / 206 |
| `PUT`, `MOVE`, `DELETE`, `MKCOL`, `LOCK`, `UNLOCK` | desktop | 201/204/200 | 405 (J2) |
| `GET /status.php` | both | 200 | 200 |
| `GET /index.php/204` | both | 204 | 204 |
| `GET /ocs/v1.php/cloud/{capabilities,user}` | desktop | 200 | 200 |
| `GET /ocs/v2.php/cloud/{capabilities,user}` | android | 200/304 | 200 |
| `GET /ocs/v2.php/apps/{user_status,notifications}/…` | desktop (every ~5 min) | 200/304 | OCS 404 (not announced in capabilities) |
| `GET /ocs/v2.php/core/navigation/apps`, `apps/terms_of_service/terms`, `apps/recommendations/…`, `apps/activity/…` | both | 200/404 | OCS 404 |
| `GET /remote.php/dav/avatars/<u>/128.png`, `/index.php/avatar/<u>/512` | both | 200 | 404 |
| `PROPFIND /remote.php/dav/versions/<u>/…` | android | 207 | 404 |

To observe with a real client on Beastbox (J1, exit): the exact properties requested in PROPFIND, whether `oc:id` is required,
the reaction to `G` permissions (read-only), to the 404s of background endpoints, and detection of a deep change after
`rescan`.

## Real session on Beastbox — desktop client, 2026-11-14 (J1)
Nextcloud desktop client on a LAN machine, server `http://files.alpha.test:8480` (test nginx). Full account setup:

1. `GET /status.php` → 200; `POST /index.php/login/v2` → 200.
2. Browser: `GET` then `POST /index.php/login/v2/flow/<token>` → 200.
3. `POST /index.php/login/v2/poll` → 404 (×10, one per second) then 200.
4. `PROPFIND /remote.php/dav/files//` **unauthenticated** → 401 (probe for the auth type, empty user).
5. `GET /ocs/v1.php/cloud/capabilities` and `GET /ocs/v1.php/cloud/user` → 200.
6. `HEAD /remote.php/dav/files/alice/` → **405 at J1: gap fixed** (sabre/dav answers 200 to a HEAD on a folder).
7. `PROPFIND` on the root then each subfolder (`Photos`, `Photos/2026`, …) → 207.
8. `GET /remote.php/dav/avatars/alice/80.png` → 404 (no visible harm); `GET /` → 404.

No calls to notifications or user status: the client honors the capabilities, which do not announce them.
Also seen: the client keeps requests open, which blocked server shutdown (fixed: shutdown bounded to 10 s).

### J1 exit criterion: deep change outside the application, then `rescan`
- 16:28:39: line added over SSH to `Photos/2026/novembre/a.txt`, then `beastbox rescan --path Photos/2026/novembre`.
- 16:29:05: the client (polling the root every ~30 s) descends **only** into the changed branch
  (`Photos` → `Photos/2026` → `Photos/2026/novembre`, `mille` not reread), then `GET a.txt` → 200.
- Detection delay: 26 s. Propagation of the folder ETag to all ancestors: **confirmed necessary and sufficient** with the real
  client (open point of §7).
- Other background calls seen: `GET /ocs/v2.php/core/navigation/apps`, `/ocs/v2.php/search/providers`,
  `/index.php/apps/theming/img/core/filetypes/text.svg`, avatars: 404 with no visible effect on sync.
- Not tested with the client: add, rename and delete outside the application (same mechanism), mobile app.

## Exact PROPFIND of the desktop client `mirall/35.0.2` (Linux, Flatpak), captured on 2026-11-14
`Depth: 1`, headers `X-Request-Id`, `Accept-Encoding: zstd, br, gzip, deflate`. Body:
`d:resourcetype`, `d:getlastmodified`, `d:getcontentlength`, `d:getetag`, `d:quota-available-bytes`, `d:quota-used-bytes`,
`oc:size`, `oc:id`, `oc:fileid`, `oc:downloadURL`, `oc:dDC`, `oc:permissions`, `oc:checksums`, `nc:is-encrypted`,
`nc:metadata-files-live-photo`, `nc:share-attributes`, `oc:share-types`, `nc:is-mount-root`.

Beastbox J2 answers 404 for: `oc:size` **of folders** (recursive size not computed), `oc:downloadURL`, `oc:dDC`,
`nc:is-encrypted`, `nc:metadata-files-live-photo`, `nc:share-attributes`, `oc:share-types`, `nc:is-mount-root` — with no
visible effect on sync at this stage. A folder's `oc:size` is shown by the client (folder size): to be handled.

### Folder quota frozen on the client side (desktop client 35.0.2, client logs, 2026-11-14)
The client records the available space **of each folder** in its local database (`folderQuota - bytesUsed / bytesAvailable`
in the folder record) and decides whether to upload a file from **that recorded value**, not from the one the server just
returned:
```
Processing "Test" | etag: "3cce…"(base) // "cd5f…"(serveur) → CSYNC_INSTRUCTION_UPDATE_METADATA
Quota exceeded for item: "Test/…iso" - item bytes used: 3091660800 - folder bytes available: 531263488
```
The folder record is only updated at the end of an **error-free** sync of that folder; but the error is precisely the quota
refusal → the value stays frozen. After a quota increase (here 1 GB → 20 GB), the file stays blocked forever, even though
Beastbox does announce the new space (`quota-available-bytes` = 20,878,745,600). A real Nextcloud server would cause the same
thing. Workaround: move the file out of the folder, let a sync finish without errors, put it back; or delete `.sync_*.db`.
Nothing to fix on the Beastbox side.

## Real J2 session — desktop client 35.0.2 (Linux, Flatpak), 2026-11-14: two-way sync
- **Photo upload**: 14 PUT → 201 (16:58).
- **2.9 GB ISO** (3,091,660,800 B) via upload v2: MKCOL `uploads/alice/1313609872` → 30 PUT of **100 MiB** (chunks named
  `00001`… on 5 digits) → MOVE `.file` → 201. Total time 59 s (~52 MB/s over LAN + test nginx). Original time kept
  (`X-OC-Mtime`). SHA-1 recorded at write time identical to the SHA-1 recomputed on disk. Upload and temporaries cleaned up.
  Before uploading, the client does a `PROPFIND` (Depth 0) on the target file → 404 expected.
- **Deletes**: DELETE → 204, items in `.trash/` (original path, author, date in xattr).
- **Restore from the OS trash** (2026-11-16): by default the desktop client also moves a deleted file to the OS trash.
  Restored from there, the client uploads it as a new file (PUT): new `fileid`, no tags, favorite or links, and the
  deleted version stays in Beastbox's trash until it expires. Nextcloud behaves the same; kept as is. To have a single
  trash (Beastbox's, restorable from the web or the app), uncheck "Move removed files to trash" in the client's settings
  (General).
- **Renames**: MOVE → 201 (no re-upload), identity kept.
- Not observed: LOCK/UNLOCK, PROPPATCH, COPY (the desktop client renames with MOVE).

## Android app: reading the sources (2026-11-14, `nextcloud/android` 270a3a1 and `nextcloud/android-library` 8f442a5)
Not yet observed for real: what follows comes from the code, to confirm with the app (§7).
- **Minimum server version**: `MainApp.MINIMUM_SUPPORTED_SERVER_VERSION = NextcloudVersion.nextcloud_23` (we announce 35).
- **Cleartext HTTP** allowed (`network_security_config.xml`: `cleartextTrafficPermitted="true"`), with a warning.
- **PROPFIND** (`WebdavUtils.getAllPropSet`): ~40 properties, including `oc:fileid` (localId), `oc:id` (remoteId), `oc:size`,
  `oc:permissions`, `d:quota-*`, `nc:lock*` locks, photo metadata, `nc:hidden`… All have a default value if absent.
- **Simple upload** (`UploadFileRemoteOperation`): `If-Match: "<etag>"`, `OC-Total-Length`, `X-OC-Mtime`, `X-OC-Ctime`
  (ignored by Beastbox); **never `OC-Checksum`**. Success: 200, 201, 204.
- **Chunked upload** (`ChunkedFileUploadRemoteOperation`), used as soon as the size exceeds 40,960,000 B on Wi-Fi
  (10,240,000 B otherwise, or `files.chunked_upload.max_size` from the capabilities) **without checking `dav.chunking`**:
  - folder `/remote.php/dav/uploads/<user>/<MD5 of the file>`; MKCOL with `Destination` **every time, response ignored**;
  - PROPFIND Depth 1 of the folder (`getcontenttype`, `resourcetype`, `getcontentlength`) to **resume**: a chunk = a name of
    at most 6 digits (`CHUNK_NAME_LENGTH = 6`), resuming starts from the sum of the sizes;
  - PUT `<folder>/000001`… with `Destination` and `OC-Total-Length`;
  - MOVE `<folder>/.file` → absolute `Destination`, `Overwrite: T`, `X-OC-Mtime`, `X-OC-Ctime` (no `OC-Total-Length`).
  Compatible with Beastbox J2: repeated MKCOL → 405 (ignored), chunks stored on 5 digits (≤ 6, accepted by the app).
- Points to observe for real: resuming an interrupted upload, and `X-OC-Ctime` (creation time not kept).

## Real session — Android app `Nextcloud-android/35.0.2`, 2026-11-15 (server: the test nginx over the LAN)
- **Login Flow v2**: OK (phone browser). A first attempt failed with 404: the server had restarted between opening the page
  and confirming (flows in memory, lost on restart); the app started a new flow, accepted.
- **Browsing**: PROPFIND Depth 1 on each opened folder → 207. `HEAD /remote.php/dav/files/alice/` → 200.
- **Upload**: photo (1.9 MB) and PDF via simple PUT → 201; before each upload, `PROPFIND` (Depth 0) of the target file.
- **MKCOL**: the app tries `Music/.thumbnails/` before `Music/` → 409, creates the parent, then retries → 201.
- **404 with no visible effect**: `GET /ocs/v2.php/apps/user_status/api/v1/predefined_statuses` (repeated), notifications
  (`GET …/notifications`, `POST …/notifications/api/v2/push`), `GET /index.php/avatar/alice/512`,
  `PROPFIND /remote.php/dav/photos/alice/albums`, `OPTIONS /remote.php/dav` (and `HEAD /remote.php/dav` → 401).
- Not yet observed: downloading (GET) a file, chunked upload (beyond 40.96 MB on Wi-Fi).

## Identities erased on a synced folder — two desktop clients, 2026-11-17 (plan J4, addition 2)
Clients: `mirall/35.0.2` (Linux, Flatpak) and `mirall/3.11.0` (Linux Mint), both syncing alice's whole space.
Folder `Pops2` (42 files, 4 folders, a tag, a favorite, a public link). Every `beastbox.*` xattr erased (times kept),
then `rescan --path Pops2`, server running; a local change made right after, during the window.
- **How the client handles an ETag change on a file of the same size and time**: `CSYNC_INSTRUCTION_SYNC` down, full `GET`
  into a hidden temporary (`.name.~xxxx`), content compared: identical → local file kept (same inode), only the journal
  updated (ETag, `fileid`). Nothing in the activity list, but **every byte is transferred**, by each client.
- **Without manifest** (0.12.0): 46 new identities; each client re-downloads the whole folder (41 and 42 `GET`); tag,
  favorite and link lost. The link, opened after the `rescan`, is **ended for good** (`end_reason = 'gone'`): a later
  `zfs rollback` brings the identity back, not the link.
- **With manifest, 0.12.0**: identities, tag, favorite and link recovered, but the ETags change (the manifest kept neither
  the SHA-1 nor the nanoseconds): full re-download again, and the file changed locally during the window became a
  **conflict** (`test-identite (conflicted copy …).txt`, server version under the name).
- **With manifest, fix (format 2)**: `47 identities recovered (42 with the same content and ETag)`; **0 `GET`** on the 41
  photos, the local change uploaded by a `PUT`, **no conflict**; link 200, tag and favorite back.
- `zfs rollback` then `rescan`: files get their ETags back, folders get new ones (`rescan` renews them): clients that saw
  the intermediate state re-download everything once more.
- Not tried: the Android app; a real `rclone` to pCloud and back (the copy loses the nanoseconds: covered by the tests).
