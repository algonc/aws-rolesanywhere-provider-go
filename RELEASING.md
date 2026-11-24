# Releasing aws-rolesanywhere-provider-go

A Git version tag is the version downstream applications use in `go get`. The [release workflow](.github/workflows/release.yml) tests the tagged source and publishes a GitHub release with generated notes and source archives.

## Choose a Version

Use a new `v0.MINOR.PATCH` or `v1.MINOR.PATCH` tag, such as `v0.1.0`. A tag such as `v0.1.0-rc.1` creates a prerelease. A `v2` or later release requires a corresponding Go module path suffix, such as `/v2`.

Keep each pushed tag on its original commit. Publish a new version if a release needs a fix.

## Prepare and Publish

Confirm CI has passed for the intended commit on `main`. Run these checks from a clean checkout of that commit before pushing the tag. Go can resolve a pushed tag before GitHub Actions finishes.

```sh
go mod tidy -diff
go mod verify
go vet ./...
go test -count=1 ./...
```

Choose the version, create an annotated tag, and push that tag.

```sh
version=v0.1.0
git tag -a "$version" -m "Release $version"
git push origin "$version"
```

The workflow validates the tag, checks the module files, and runs tests and vet on Linux, macOS, and Windows. It also runs the race detector on Linux. After the checks pass, GitHub publishes the release. Prereleases are excluded from the latest GitHub release.

## Verify the Release

Check the GitHub release and its generated notes. From a consuming Go module, pin the new version and run the application's tests.

```sh
go get github.com/algonc/aws-rolesanywhere-provider-go@v0.1.0
go test ./...
```

For a temporary workflow failure, check whether the GitHub release exists before rerunning the failed jobs. If a source change is required, commit the fix and push a new version tag.
