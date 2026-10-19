# Git and PyPI release procedure

The source export is a standalone repository: `src/aicaah/`, public documentation, examples, CI, MIT license and packaging metadata. Original project documents, review approvals, snapshots, caches, assets, credentials and project-only tests are excluded. `MANIFEST.json` records SHA-256 hashes of the exported files at export time; it is provenance, not a substitute for Git tracking after subsequent edits.

## Prepare and upload the Git repository

From a development checkout, use the public `export --destination NEW_DIRECTORY` command to generate a fresh bundle. Existing directories are rejected. Inspect the generated file list and build it before publishing. When working in the original host repository, use its documented engine entry point.

Inside the exported folder:

```sh
git init -b main
git add .
git diff --cached --stat
git commit -m "Prepare AICAAH 0.1 beta"
```

Create your chosen empty remote repository, set its real URL with `git remote add origin YOUR_REPOSITORY_URL`, then `git push -u origin main`. Replace the placeholder; no remote account or URL is embedded in this bundle. Add the real homepage/repository/issues URLs to `[project.urls]` before publishing so PyPI users can find support. The current Markdown links work in the source repository; absolute repository links are preferable in the eventual PyPI README.

## Verify the release artifacts

```sh
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m pip install dist/aicaah-0.1-py3-none-any.whl
python -m pip check
python -m aicaah selftest --portable
python scripts/benchmark.py --files 100 --repeats 3 --output benchmark.json
```

Test a clean install of the wheel and of a wheel rebuilt from the sdist. Do not reuse an already uploaded version for different contents. `0.1` is the agreed version string; the Beta classifier describes maturity without changing that spelling.

## Register a trusted publisher

PyPI publication needs the package owner's account and a configured project/pending trusted publisher. The public-name endpoint returning 404 does not guarantee that a name is allocatable; restrictions are checked when creating the project.

Register the exact GitHub owner, repository, workflow filename `publish.yml` and environment `pypi`. Create the matching GitHub environment, with release approval rules appropriate for the repository. The workflow uses short-lived OIDC credentials and contains no token. For a new project follow the [PyPI trusted-publisher setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/); the [publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/) explains the token exchange.

Push an annotated release tag `v0.1` after the desired CI matrix has passed. Run the **Publish to PyPI** workflow manually on that tag with input `0.1`. It refuses a mismatched tag/version and builds, validates, installs and tests before uploading. Repository creation, tags and actual registry upload are separate user-controlled publishing actions; exporting or installing AICAAH performs none of them.

If testing the workflow on TestPyPI, register that index separately and set the action's `repository-url` to `https://test.pypi.org/legacy/`. Do not confuse a TestPyPI upload with production availability. Avoid mixing untrusted extra package indexes into ordinary installation.

## Verify public availability

After successful production publication, install `aicaah==0.1` in a fresh Python environment from PyPI and run `aicaah --version` and `aicaah selftest --portable`. Only then update the pre-publication notices in the README translations and changelog. Record artifact hashes, tested platforms and actual benchmark results in the release notes.

Packaging format reference: [Python Packaging User Guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/).
