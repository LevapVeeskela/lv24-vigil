# AUR (vigil-bin)

`vigil-bin` is the Arch User Repository package for the prebuilt Vigil release
binary. It installs `/usr/bin/vigil` and the Apache-2.0 license; nothing is
compiled locally.

The packaging in this repository is ready for **0.9.3**, but the package is not
published yet. Publishing needs an AUR account and an SSH key, so it is a manual
account-gated step (see [Publish](#publish-to-the-aur)). AUR registration is
currently paused (HTTP 503, no manual queue); wait for the aur-general/Arch news
announcement and do not script retries.

## Install

After the package appears on AUR:

```bash
yay -S vigil-bin
# or
paru -S vigil-bin

vigil version   # 0.9.3
```

Without an AUR helper:

```bash
git clone https://aur.archlinux.org/vigil-bin.git
cd vigil-bin
makepkg -si
```

The package installs:

| Path | Content |
|---|---|
| `/usr/bin/vigil` | statically linked release binary, mode `0755` |
| `/usr/share/licenses/vigil-bin/LICENSE` | Apache-2.0 text |

`provides=('vigil')` and `conflicts=('vigil')` mean the package satisfies a
dependency on `vigil` and does not coexist with another package that owns the
same command.

## Verify the checksums

The 0.9.3 PKGBUILD records the published checksums for both architectures and
the LICENSE file. For every new release, refresh all three from `checksums.txt`
before building or pushing.

Upstream publishes SHA-256 sums in `checksums.txt` for every release:

```bash
curl -fsSLO https://github.com/LevapVeeskela/lv24-vigil/releases/download/v0.9.3/checksums.txt
grep -E 'vigil_0\.9\.3_linux_(amd64|arm64)$' checksums.txt
```

Copy the `amd64` hash into `sha256sums_x86_64` and the `arm64` hash into
`sha256sums_aarch64`. For the license file:

```bash
curl -fsSL -o LICENSE https://raw.githubusercontent.com/LevapVeeskela/lv24-vigil/v0.9.3/LICENSE
sha256sum LICENSE
```

Copy that hash into `sha256sums`. A filled PKGBUILD looks like:

```bash
sha256sums=('9f1c...64-hex...')
sha256sums_x86_64=('4b2e...64-hex...')
sha256sums_aarch64=('a70d...64-hex...')
```

The signed source of truth is `checksums.txt`. To verify its cosign bundle:

```bash
gh release download v0.9.3 --pattern checksums.txt --pattern checksums.txt.sigstore.json
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/LevapVeeskela/lv24-vigil/.github/workflows/release.yml@refs/tags/v0.9.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

On an Arch machine, verify the package sources and build:

```bash
makepkg --verifysource   # downloads and checks every hash, must pass
makepkg -si              # builds the package and installs it
namcap PKGBUILD          # optional lint
```

`makepkg` is Arch-only. Without an Arch machine, compare the hashes manually as
shown above; never publish a PKGBUILD whose checksums do not match the release.

## Build from this checkout

The AUR files live in [`packaging/aur/`](../packaging/aur/):

```bash
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO /tmp/vigil-bin/
cd /tmp/vigil-bin
# verify the recorded checksums first
makepkg --printsrcinfo > .SRCINFO   # keeps .SRCINFO generated, not hand-edited
makepkg -si
```

The checked-in `.SRCINFO` matches the PKGBUILD for 0.9.3. Regenerate it whenever
the PKGBUILD changes; `makepkg --printsrcinfo` is authoritative.

## Publish to the AUR

1. Create an account at <https://aur.archlinux.org> and sign in.
2. Add your public SSH key under **My Account**. AUR accepts git over SSH only
   for writes; generate a key if needed:

   ```bash
   ssh-keygen -t ed25519 -C "aur"
   cat ~/.ssh/id_ed25519.pub
   ```

3. Test the key:

   ```bash
   ssh aur@aur.archlinux.org help
   ```

   The AUR prints its help text when authentication works.

4. Clone the package repository. For a package that does not exist yet, create
   an empty repository with the same remote:

   ```bash
   git clone ssh://aur@aur.archlinux.org/vigil-bin.git
   # if cloning reports that the repository is empty/does not exist:
   mkdir vigil-bin && cd vigil-bin
   git init
   git remote add origin ssh://aur@aur.archlinux.org/vigil-bin.git
   ```

5. Copy both files, regenerate `.SRCINFO` on an Arch host, and commit:

   ```bash
   cp /path/to/lv24-vigil/packaging/aur/PKGBUILD .
   cp /path/to/lv24-vigil/packaging/aur/.SRCINFO .
   makepkg --printsrcinfo > .SRCINFO   # requires makepkg; skip only if the pair is already in sync
   git add PKGBUILD .SRCINFO
   git commit -m "Add vigil-bin 0.9.3-1"
   git push
   ```

6. The package page is then
   <https://aur.archlinux.org/packages/vigil-bin>. AUR does not host binaries:
   `makepkg` downloads the release asset from GitHub.

The maintainer line in the PKGBUILD must name you and your AUR account email;
verify the release checksums before the first push.

## Update for a new release

1. Bump `pkgver` and reset `pkgrel=1`.
2. Replace all three checksums from the new `checksums.txt` and `LICENSE`.
3. Run `makepkg --verifysource` and `makepkg -si` on Arch (or verify hashes
   manually and update `.SRCINFO`).
4. Regenerate `.SRCINFO`:

   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```

5. Commit and push:

   ```bash
   git commit -am "upgpkg: vigil-bin 0.9.3-1"
   git push
   ```

## Notes

- **aarch64** uses `vigil_<version>_linux_arm64`; `package()` maps `CARCH` to
  the release asset suffix (`amd64` / `arm64`). The two hashes are independent.
- **No build step.** `options=('!strip')` is required because the binary is
  prebuilt and statically linked; stripping it is not the packager's job.
- **License.** Apache-2.0 is a common license, but the package still installs
  the upstream text under `/usr/share/licenses/vigil-bin/` so the exact release is
  auditable.
- **npm alternative.** `npm i -g lv24-vigil@0.9.3` installs the same CLI
  without pacman; use one install method per machine to avoid two `vigil`
  binaries on `PATH`.
- **AUR etiquette.** Keep `pkgrel` at `1` for a new upstream version, do not
  commit downloaded tarballs, and keep `.SRCINFO` in the same commit as the
  PKGBUILD.
