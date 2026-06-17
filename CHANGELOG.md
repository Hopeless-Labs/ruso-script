# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Evidence statements must name an explicit source.** Grammar is now
  `evidence <probe>.body | .response | .header "<name>"`, each with an optional
  trailing `regex '…'`. The source-less `evidence <probe> regex '…'` form is
  removed (hard parse error) — it ran against the body and could not prove a
  header-borne finding. Header values are now first-class evidence.

## [1.0.0] - 2026-06-16

Initial 1.0 release.
