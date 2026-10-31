# Trusted Publishing and attestations

This is the rollout checklist for keylocker's tokenless PyPI publishing workflow.
Preparing or merging the workflow is not a release: publishing is limited to pushes
of tags matching `v*.*.*`, after all six Python test jobs pass.

## Configure PyPI before creating the next release tag

Sign in to PyPI with an account that can manage keylocker. Open **Your projects →
keylocker → Manage → Publishing**, then add a GitHub Actions Trusted Publisher
([PyPI setup guide](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)).

Use the following exact values for this repository:

| Field | Value |
| --- | --- |
| PyPI project | `keylocker` (the existing project, not a pending new project) |
| Repository owner | `vpuhoff` |
| Repository name | `keylocker` |
| Workflow filename | `python-publish.yml` |
| Environment name | `pypi` |

The filename identifies `.github/workflows/python-publish.yml`, not the workflow's
display name. Keep the publisher's environment value aligned with `environment:
name: pypi` in the `deploy` job
([PyPI setup guide](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)).

Adding this publisher is a required manual rollout step; a successful pull-request
test run does not establish that the PyPI-side identity has been configured.
There is intentionally no fallback to the existing `PYPI_API_TOKEN` secret.

## Review GitHub release controls

The repository already has a GitHub environment named `pypi`. At preparation time
it has no required reviewers or deployment branch/tag restrictions; this PR does
not change those settings.

Before the next release, review whether that environment should require a
maintainer's approval and restrict deployments to release tags. Also review
repository tag rules for `v*`; PyPI recommends dedicated deployment environments,
required reviewers, and protected release tags
([PyPI security model](https://docs.pypi.org/trusted-publishers/security-model/)).

A workflow `if` condition is not a substitute for repository/environment access
controls. The OIDC permission and PyPI publisher identity should be treated as
publishing credentials
([PyPI security model](https://docs.pypi.org/trusted-publishers/security-model/)).

## Workflow behavior

- **Tests:** Python 3.10 through 3.15 run without `id-token: write`.
- **Build:** Only the Python 3.10 matrix job builds and uploads
  `dist-python-3.10`; its files are reused without rebuilding in `deploy`.
- **Publish:** `deploy` waits for the entire matrix, runs only on release-tag
  pushes, and uses environment `pypi`.
- **Least privilege:** Only `deploy` receives `id-token: write`; it downloads
  artifacts without checking out or executing project source.
- **Authentication:** No username, password, or `PYPI_API_TOKEN` is passed to the
  publishing action. Trusted Publishing requires `id-token: write` and a matching
  publisher registered on PyPI
  ([PyPI publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/)).
- **Attestations:** `attestations: true` explicitly requests signed attestations
  for each uploaded distribution using the GitHub workflow identity
  ([PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish)).
- **Action pin:** The publishing action is pinned to
  `7245906fb61fa33a13554f9d5fb856fe61758086`, corresponding to
  [v1.14.3](https://github.com/pypa/gh-action-pypi-publish/releases/tag/v1.14.3).

These are publishing attestations. They attest to the workflow identity that
uploaded a particular file; they are not a separate SLSA build attestation and do
not certify that the code is safe
([PyPI provenance guide](https://docs.pypi.org/using-pypi/package-security/provenance/)).

## First release after migration

1. Register the exact PyPI publisher above, then merge the workflow into the
   release branch (`master`) before creating a release tag.
2. Choose a new, unpublished version, update `pyproject.toml`, and use a matching
   tag, for example version `0.4.9` and tag `v0.4.9`. This checklist does not
   authorize creating that release; do not move `v0.4.8` or retry its upload.
3. Wait for the six test jobs, artifact build, and `Deploy to PyPI` to succeed.
   If environment approval is configured, approve the intended release run.
4. Open the new release's Security/Provenance view on PyPI and check that every
   distribution has provenance referencing `vpuhoff/keylocker`,
   `python-publish.yml`, and the expected release ref/commit
   ([PyPI provenance guide](https://docs.pypi.org/using-pypi/package-security/provenance/)).
5. After a successful OIDC publication, revoke the old publishing token on PyPI
   and delete the repository's `PYPI_API_TOKEN` secret. Check other legitimate
   consumers before revoking a shared token; revocation and secret deletion are
   separate maintainer actions, not performed by this PR.

The existing 0.4.8 files were uploaded without attestations. This workflow change
does not add provenance retroactively to those files; validate provenance on the
next release.

## Validation limits and failure handling

PR and branch-push CI validates the six Python versions and the package build;
the publishing job must remain skipped. End-to-end PyPI authentication and
attestation upload are only validated by an authorized release-tag run after
the publisher has been registered.

If OIDC authorization fails, compare the repository owner, repository name,
workflow filename, and environment with PyPI's registered publisher, then check
the job's `id-token: write` permission
([PyPI publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/)).
Fix the registration or workflow before retrying; do not silently switch back
to token-based uploads, disable attestations, or enable `skip-existing` to mask
a partial release. Inspect the PyPI release before retrying any upload.
