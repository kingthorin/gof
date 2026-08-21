# Changelog for Good Old Files (GOF)

All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Active scan rule that probes for backup/editor/old-version file variants at every discovered path using configurable permutation strategies (extension append/replace/switch, filename/directory suffix/prefix).
- Self-contained on-demand invocation via "Attack with Good Old Files" context menu (rule excluded from default policies, AlertThreshold.OFF by default).
- Custom Pages + Analyser soft-404 detection inherited from AbstractPlugin.
