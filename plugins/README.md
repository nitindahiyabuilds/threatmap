# ThreatMap scanner plugins

ThreatMap discovers scanner plugins automatically from this directory. Each Python file should export exactly one `plugin` object of type `ScannerPlugin`.

## Add a scanner

1. Create `plugins/mytool.py`.
2. Define a `ScannerPlugin` with its name, category, required flag, binary, install hint, dependencies, condition, and command/run implementation.
3. Add `mytool: true` to the desired profiles in `config/scan_profiles.yaml`.
4. Run the test suite / a local scan and verify the expected raw and evidence artifacts.

You do **not** edit `core/scanner_core.py` or `main.py` to register a plugin. The registry imports every module in `plugins/`, validates the plugin metadata, applies the selected profile, evaluates runtime conditions, and topologically orders dependencies.

## Categories

- `osint` — passive/discovery work
- `fingerprint` — service/web fingerprinting
- `port_scan` — port and service discovery
- `web` — web-facing scanners
- `vuln` — vulnerability detection

## Behavioral compatibility

Plugin implementations should preserve the existing command flags, timeouts, raw filenames, and evidence filenames when replacing an existing scanner. The registry is an orchestration layer, not a reason to change scan behavior.
