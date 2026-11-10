# Repository history and size

This page records one historical accident in this repository: a release asset
directory that was committed by mistake and removed one commit later. The blobs
are still reachable from `v0.2.0` and later, so `.git` carries roughly 17.5 MiB
of dead weight. The history is **intentionally not rewritten**. This page keeps
the measurements, the reasoning, and the procedure in case that decision ever
changes.

## What happened

| Commit | Date | Change |
|---|---|---|
| `1c57bae` | 2026-11-10 | `dist-0.1.4/` added: four GoReleaser binaries plus `checksums.txt` (40 MiB uncompressed) |
| `601dfc3` | 2026-11-10 | `dist-0.1.4/` removed; `/dist-*/` added to `.gitignore` |

The directory was a local download of the `v0.1.4` release assets, committed
while verifying npm Trusted Publishing. `601dfc3` removed it from the working
tree and from every later commit, but a deletion only removes the blobs from the
tip. `1c57bae` is an ancestor of `main`, so all five blobs stay in the object
database and in every clone.

The `v0.1.x` tags are safe: `v0.1.4` is `b17cdd7`, the parent of `1c57bae`, so
no `v0.1.x` tag contains the accidental commit. `v0.2.0`, `v0.2.1`, `v0.3.0` and
`v0.4.0` do contain it.

## Measurements (2026-11-10)

| Metric | Value |
|---|---|
| `.git` total, local clone | 18.50 MiB (517 loose objects, no pack) |
| `dist-0.1.4` blobs on disk | 17.52 MiB / 18,367,146 bytes (95% of `.git`) |
| The same files uncompressed | 39.98 MiB |
| Server-side repository size (GitHub API `size`) | 12,297 KB ≈ 12.0 MiB |
| Commits that a rewrite would change | 12 descendants of `1c57bae`, 13 including it |
| Tags that would have to move | `v0.2.0`, `v0.2.1`, `v0.3.0`, `v0.4.0` |
| GitHub releases already published | 9 (`v0.1.0` … `v0.4.0`) |

Per file, as stored (zlib) and as reported by `git cat-file -s`:

| Path | Stored | Raw |
|---|---|---|
| `dist-0.1.4/checksums.txt` | 316 B | 554 B |
| `dist-0.1.4/vigil_0.1.4_darwin_amd64` | 4,868,324 B | 11,002,832 B |
| `dist-0.1.4/vigil_0.1.4_darwin_arm64` | 4,418,054 B | 10,184,402 B |
| `dist-0.1.4/vigil_0.1.4_linux_amd64` | 4,804,278 B | 10,776,736 B |
| `dist-0.1.4/vigil_0.1.4_linux_arm64` | 4,276,174 B | 9,961,632 B |

Compiled Go binaries are close to incompressible, so zlib only recovers about
half of the raw size and GitHub's repack recovers a little more. Expect the
server-side figure to keep drifting down slightly as GitHub repacks; it will
never reach zero while the commits are reachable.

## Why the history is not rewritten

1. **Go module tags are immutable.** `proxy.golang.org` already serves all nine
   tags, and `sum.golang.org` has recorded a permanent checksum per version —
   `v0.2.0` is `h1:PyJCiBdGpon73l5L6kBUuGHkjLWuDja9w1S2GcpZnv4=`. Rewriting a
   tagged commit changes the module zip, so `go get` fails with a checksum
   mismatch against the sum database. A moved tag cannot be repaired; it can
   only be superseded by a new version.
2. **Provenance links point at those commits.** npm publishes from `0.1.4`
   onward carry SLSA attestations that name the workflow run and commit, and
   every GitHub release is bound to its tag's commit. Moving the tags turns
   working links into 404s or mismatched attestations.
3. **Public repository, existing clones and forks.** A force-push does not
   delete anything from clones, forks, mirrors or caches. Those copies keep the
   old SHAs, and every contributor has to re-clone instead of pulling.
4. **The cost is bounded and small.** 12 MiB server-side, 17.5 MiB locally, and
   nothing in the working tree. Fresh clones pay it once. That does not justify
   invalidating published versions.
5. **The gain is only cosmetic.** A rewrite does not make the repository faster,
   safer or easier to install. It changes SHAs everywhere for a one-off mistake
   that is already removed from the tip.

## If a rewrite ever becomes necessary

Treat this as a versioned, announced operation, not a cleanup. Preconditions:
no other pushes or tags in flight, maintainer access to force-push `main` and
tags, and acceptance that already published Go and npm versions cannot be
re-pointed.

```bash
# 1. Freeze the repository: no pushes, no tags, no releases until done.

# 2. Back up everything before touching history.
git bundle create ../lv24-vigil-backup.bundle --all
git bundle verify ../lv24-vigil-backup.bundle
cp -r .git ../lv24-vigil-backup.git

# 3. Rewrite: drop the path from every commit.
git filter-repo --path dist-0.1.4 --invert-paths --force

# 4. Recreate the tags at the rewritten commits, deliberately.
git tag v0.2.0 <new-sha-for-0.2.0>
git tag v0.2.1 <new-sha-for-0.2.1>
git tag v0.3.0 <new-sha-for-0.3.0>
git tag v0.4.0 <new-sha-for-0.4.0>

# 5. Push with lease, never with plain --force.
git push --force-with-lease origin main
git push --force-with-lease origin --tags

# 6. Validate from a clean directory.
git clone https://github.com/LevapVeeskela/lv24-vigil.git ../lv24-vigil-verify
git -C ../lv24-vigil-verify fsck --full
git -C ../lv24-vigil-verify count-objects -vH
```

Then tell every contributor to **re-clone**; `git pull` will not converge on a
rewritten history. Bump to the next version for Go and npm so the checksum and
provenance records match the new commits, and re-upload release assets if a
release ends up pointing at a commit that no longer exists.

Risks, in order of severity:

- **Permanent checksum mismatch** for every Go version already in the sum
  database — unfixable, only avoidable by never moving a tag.
- **Dead provenance and release links** for `0.2.0` and later.
- **Broken forks and stale clones** that keep pushing the old SHAs back.
- **No undo without the bundle.** If the backup is missing or unverified, the
  original history is gone.
- **CI surprises:** every workflow run pinned to an old SHA becomes unreachable.

## Rules going forward

- Release assets live in GitHub releases only. `/dist-*/`, `/dist/`,
  `/npm-out/`, `/bin/` and `*.exe` are gitignored, and they stay that way.
- The release workflows download assets into `release-assets/`; nothing under
  that path is ever committed.
- Before committing, check `git diff --cached --stat`. A staged file of
  megabytes is a mistake, not an asset.
- If a binary genuinely has to live in git, that is a design change: use Git
  LFS and record the decision, rather than committing the binary directly.

See also: [release.md](release.md) for the release pipeline and asset handling,
[install.md](install.md) for the user-facing download paths.
