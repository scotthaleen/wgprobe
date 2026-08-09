# Releasing

Releases are built only from an existing `vMAJOR.MINOR.PATCH` tag. The tag must
point to a commit that contains the release workflow and matching versions in all
three Cargo packages. Before the first release, enable release immutability under
the repository's **Settings > Releases** section.

1. Update the package versions and user-facing release documentation in a pull
   request.
2. Run the full CI suite and merge the pull request.
3. Tag the merge commit and push the tag:

   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. Confirm that the Release workflow publishes eight native archives, four ABI3
   wheels, `install.sh`, `SHA256SUMS`, and GitHub artifact attestations.
5. Verify one Linux installer path and one Homebrew installation before
   announcing the release.
6. Update both formulas in a follow-up pull request. Set their version, source
   URL, and SHA-256 checksum to the new release source archive, then run `brew
   style`, `brew audit --strict`, `brew install --build-from-source`, and `brew
   test` for each formula.

Published releases are immutable. A failed draft can be deleted and rebuilt, but
an existing published release must not be overwritten.
