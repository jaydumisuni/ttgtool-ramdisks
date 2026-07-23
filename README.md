# TechGuyTool Ramdisks

Private/package metadata and local provider-pack tooling for iOS service ramdisks used by TGCHECKM8 and TechGuyTool.

This repository does not need to commit Apple images or commercial archives. Exact packages remain local; the repository stores schemas, templates, hashes, provenance, and reviewed device/build mappings.

## File naming

`{device_id}-{board}_ios{major}`

## Devices covered

| Device | Model | iOS |
|---|---|---|
| iPhone 6 | iPhone7,2 | 12 |
| iPhone 6 Plus | iPhone7,1 | 12 |
| iPhone 6s | iPhone8,1 | 11-15 |
| iPhone 6s Plus | iPhone8,2 | 12-15 |
| iPhone SE 1st | iPhone8,4 | 15 |
| iPhone 7 | iPhone9,1 / 9,3 | 11-15 |
| iPhone 7 Plus | iPhone9,2 / 9,4 | 11-15 |
| iPhone 8 | iPhone10,1 / 10,4 | 11-16 |
| iPhone 8 Plus | iPhone10,2 / 10,5 | 12-16 |
| iPhone X | iPhone10,3 / 10,6 | 11-16 |
| iPad Air 2 | iPad5,3 / 5,4 | 15-16 |
| iPad mini 4 | iPad5,1 / 5,2 | 16 |
| iPad Pro 9.7 | iPad6,3 / 6,4 | 16 |
| iPad 5th gen | iPad6,11 / 6,12 | 15-16 |
| iPad Pro 10.5 | iPad7,3 / 7,4 | 16 |
| iPad 6th gen | iPad7,5 / 7,6 | 16-17 |
| iPad 7th gen | iPad7,11 / 7,12 | 16-18 |

## Provider-pack workflow

1. Obtain or build a tested package locally.
2. Inventory it without execution or extraction:

```bash
python scripts/inventory_package.py /path/to/package.zip --output inventory.json
```

3. Copy `templates/a8-a11-gaster-sshrd.template.json` to a device/build-specific private manifest.
4. Fill the exact product, board, CPID, firmware build, inventory asset records, and reviewed boot recipe.
5. Validate against `schemas/provider-pack-v1.schema.json`.
6. Import the resulting metadata into TGCHECKM8 for hardware verification.

The inventory tool rejects path traversal, symbolic links, duplicate case-insensitive paths, oversized archives/members, empty members, and duplicate classified asset roles. It calculates SHA-256 values while streaming the ZIP and never executes or extracts package contents.

## Known A8-A11 source recipe

- Gaster source: `0x7ff/gaster` at `7fffffff38a1bed1cdc1c5bae0df70f14395129b`, Apache-2.0.
- SSHRD source: `verygenericname/SSHRD_Script` at `d99ec4a19172b87d80fd9dea25eabf39291425a0`, BSD-3-Clause.

Remote catalogues are discovery/reference sources only. No remote entry becomes executable trust without a local device/build manifest and exact hashes.
