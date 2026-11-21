# Upgrade

1. Read "**Before upgrading**" in `CHANGELOG.md` for every skipped version.
2. Have a recent backup (`backup.md`).

```sh
git checkout vX.Y.Z && cargo build --release --locked
service beastbox stop
install -m 0555 target/release/beastbox /usr/local/bin/
service beastbox start
beastbox --version                 # also in the web page footer
```

Database migration: automatic at startup, after a copy to `state_dir/app.vN-<date>.bak`. If something goes wrong: stop, put
that copy back in place of `app.db`, reinstall the previous binary. A database newer than the binary is refused.
