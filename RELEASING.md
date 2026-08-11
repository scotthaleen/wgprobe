# Releasing

Patch releases use a version-bump pull request. Merging that pull request creates
the version tag and starts the artifact build. The release workflow rejects any
version change that is not exactly one patch above the version in the parent
commit.

Before the first release, enable release immutability under **Settings >
Releases**. The `release-preparation` and `pypi` environments must allow
deployments only from `master`. Keep the default `GITHUB_TOKEN` permission
read-only. The workflows grant write access only to the jobs that open the pull
request, create the tag, attest artifacts, or publish the release.

Under **Settings > Actions > General**, enable **Allow GitHub Actions to create
and approve pull requests**. The preparation workflow needs this repository
setting to create the version-bump pull request. It does not approve the pull
request.

Configure `wgprobe` under **PyPI > Manage > Publishing** with this trusted
publisher:

| Field | Value |
| --- | --- |
| Owner | `scotthaleen` |
| Repository | `wgprobe` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

The PyPI job uses OpenID Connect. Do not add a PyPI API token to GitHub.

## Publish a patch release

1. Merge the changes that the release must contain into `master`.
2. Open **Actions > Prepare patch release > Run workflow** and run the workflow
   from `master`.
3. Open the generated `Release vMAJOR.MINOR.PATCH` pull request.
4. Approve its workflow runs when GitHub requests approval. GitHub requires this
   approval for pull requests created with `GITHUB_TOKEN`.
5. Confirm that the pull request changes all three Cargo package versions, the
   two internal `wgprobe` dependency requirements, and `Cargo.lock`.
6. Wait for the full CI suite, then squash-merge the pull request.
7. Confirm that the Release workflow creates the matching tag and publishes:

   - eight native archives;
   - five Python 3.10+ ABI3 wheels;
   - `install.sh`;
   - `SHA256SUMS`; and
   - GitHub artifact attestations.

8. Confirm that PyPI contains the five wheels and that an isolated
   `wgprobe==MAJOR.MINOR.PATCH` installation succeeds.
9. Test one Linux installer path and one Homebrew installation before announcing
   the release.

The version can also be prepared locally with:

```sh
./scripts/bump-version.sh patch
```

The script updates the package manifests and lockfile. It does not create a
commit, tag, or release.

## Update Homebrew formulas

Update both formulas in a follow-up pull request. The formula checksum cannot be
part of the release commit because the checksum covers a source archive that
contains the formula itself.

1. Set each formula's version and URL to the new tagged source archive.
2. Set each formula's SHA-256 checksum to that archive's checksum.
3. Run `brew style` and `brew audit --strict` for both formulas.
4. Run source installation and `brew test` for both formulas on macOS and Linux.

## Recover a failed release

- Rerun release preparation after a transient PR-creation failure. The workflow
  reuses an existing release branch only when its file tree exactly matches the
  generated version bump.
- If release preparation reports unexpected branch content, inspect the existing
  `release/vMAJOR.MINOR.PATCH` branch. Delete it only when it is stale and no
  release work depends on it.
- If artifact construction fails before a release exists, rerun the Release
  workflow with the existing tag.
- If a draft release exists, delete the draft before rerunning the workflow.
- If PyPI publication fails, rerun the failed job after correcting the trusted
  publisher. The publish command skips an existing file only when it matches the
  wheel that the workflow produced.
- Never move or overwrite a tag for a published immutable release. Prepare the
  next patch release instead.
