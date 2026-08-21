# Good Old Files (GOF) - ZAP Add-on

A ZAP add-on that probes for backup, editor-swap, old-version, and copy variants of files discovered during active scanning. Useful for finding exposed backup files, unversioned copies, or editor temporary files.

## Features

- Detects multiple backup/copy file variants through configurable permutation strategies
- Operates as an optional active scan rule (disabled by default, enable via right-click context menu or policy)
- Integrated with ZAP's soft-404 detection (Custom Pages + Analyser)
- Configurable wordlists with disable/custom entry support

## Building

Deploy and test the add-on locally using:

```bash
./gradlew copyZapAddon
```

## Attribution

Based on the original [good-old-files extension](https://github.com/hacktics/good-old-files) by Hacktics (Ernst & Young), 2014.

## More Information

For more info on developing ZAP add-ons see https://www.zaproxy.org/docs/developer/