#!/usr/bin/env python3
"""
exif_tool.py — Read, display, add to, and optionally strip EXIF metadata from images.

Dependencies:
    pip install Pillow piexif

Usage:
    python exif_tool.py photo.jpg
    python exif_tool.py photo1.jpg path/to/photo2.png path/to/photo3.jpg
    python exif_tool.py # interactive mode (prompts for paths)
"""

# Each image is scanned and EXIF fields printed. You are then prompted to strip, add, or edit metadata.
# Strip: 'y' strips with backup (<name>.backup.<ext>), 'b' strips without saving a backup, enter skips.
# Add/edit: choose merge (keeps existing, overwrites selected fields) or wipe (clears all fields first).
# Supports JPEG, TIFF, PNG and most Pillow-readable formats. 
# Requires: pip install Pillow piexif (these are in requirements.txt)

import sys
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import piexif # type: ignore
except ImportError:
    print('Error: required libraries not found.')
    print('Install them with: pip install Pillow piexif')
    sys.exit(1)


# Dataclasses
@dataclass
class ExifField:
    tag: str
    raw_value: Any
    display_value: str

@dataclass
class ExifReport:
    path: Path
    has_exif: bool
    fields: list[ExifField] = field(default_factory=list[ExifField])
    error: str | None = None


# EXIF reading
def _decode_gps_coord(values: tuple[Any, ...]) -> float:
    """Convert a GPS coordinate tuple of rationals to decimal degrees."""
    def ratio(val: Any) -> float:
        if isinstance(val, tuple):
            return val[0] / val[1] if val[1] != 0 else 0.0 # type: ignore
        return float(val) # IFDRational supports __float__
    degrees = ratio(values[0])
    minutes = ratio(values[1]) / 60
    seconds = ratio(values[2]) / 3600
    return degrees + minutes + seconds

def _format_gps(gps_data: dict[str, Any]) -> list[ExifField]:
    """Parse raw GPS IFD into human-readable fields."""
    fields: list[ExifField] = []
    lat_val = gps_data.get('GPSLatitude')
    lat_ref = gps_data.get('GPSLatitudeRef', 'N')
    lon_val = gps_data.get('GPSLongitude')
    lon_ref = gps_data.get('GPSLongitudeRef', 'E')
    alt_val = gps_data.get('GPSAltitude')
    alt_ref = gps_data.get('GPSAltitudeRef', 0)

    if lat_val and lon_val:
        lat = _decode_gps_coord(lat_val)
        lon = _decode_gps_coord(lon_val)
        if lat_ref == 'S':
            lat = -lat
        if lon_ref == 'W':
            lon = -lon
        fields.append(ExifField(
            tag='GPS Coordinates',
            raw_value=(lat_val, lon_val),
            display_value=f'{lat:.6f}°, {lon:.6f}°  '
                          f'(https://maps.google.com/?q={lat:.6f},{lon:.6f})',
        ))

    if alt_val is not None:
        try:
            metres = alt_val[0] / alt_val[1]
            below  = isinstance(alt_ref, int) and alt_ref == 1
            fields.append(ExifField(
                tag='GPS Altitude',
                raw_value=alt_val,
                display_value=f'{metres:.1f} m {"below" if below else "above"} sea level',
            ))
        except (ZeroDivisionError, TypeError):
            pass

    for key, value in gps_data.items():
        if key not in ('GPSLatitude', 'GPSLatitudeRef',
                       'GPSLongitude', 'GPSLongitudeRef',
                       'GPSAltitude', 'GPSAltitudeRef'):
            fields.append(ExifField(
                tag=f'GPS {key.removeprefix("GPS")}',
                raw_value=value,
                display_value=str(value),
            ))

    return fields


def _safe_str(value: Any) -> str:
    """Convert an EXIF value to a printable string."""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], int): # type: ignore
        # Rational number
        if value[1] == 0:
            return 'undefined'
        return f'{value[0] / value[1]:.4f}'.rstrip('0').rstrip('.')
    return str(value) # type: ignore


def read_exif(path: Path) -> ExifReport:
    """Open an image and extract all EXIF fields into an ExifReport."""
    if not path.exists():
        return ExifReport(path=path, has_exif=False, error='File not found')
    if not path.is_file():
        return ExifReport(path=path, has_exif=False, error='Path is not a file')

    try:
        image = Image.open(path)
    except Exception as exc:
        return ExifReport(path=path, has_exif=False, error=f'Cannot open image: {exc}')

    raw_exif = image._getexif() # type: ignore[attr-defined]
    if raw_exif is None:
        return ExifReport(path=path, has_exif=False)

    fields: list[ExifField] = []
    gps_ifd: dict[str, Any] = {}

    for tag_id, value in raw_exif.items(): # type: ignore
        tag_name = TAGS.get(tag_id, f'Tag_{tag_id}') # type: ignore

        if tag_name == 'GPSInfo' and isinstance(value, dict):
            for gps_id, gps_val in value.items(): # type: ignore
                gps_key = GPSTAGS.get(gps_id, f'GPS_{gps_id}') # type: ignore
                gps_ifd[gps_key] = gps_val
            continue

        if tag_name == 'UserComment' and isinstance(value, bytes):
            charset = value[:8].rstrip(b'\x00').decode('ascii', errors='ignore').strip()
            text = value[8:]
            if charset == 'UNICODE':
                display = text.decode('utf-16', errors='replace').strip('\x00')
            else:
                display = text.decode('utf-8', errors='replace').strip('\x00 ')
            display = display if display.strip() else '[empty]'

        if tag_name == 'MakerNote' and isinstance(value, bytes):
            display = f'[{len(value)} bytes binary data]'
        else:
            display = _safe_str(value)

        fields.append(ExifField(tag=tag_name, raw_value=value, display_value=display))

    if gps_ifd:
        fields.extend(_format_gps(gps_ifd))

    fields.sort(key=lambda f: f.tag)
    return ExifReport(path=path, has_exif=True, fields=fields)

# EXIF stripping
def strip_exif(path: Path, backup: bool = True) -> tuple[bool, str]:
    """
    Remove all EXIF data from the image at `path`.

    If `backup` is True, saves the original as <name>.backup.<ext> first.
    Returns (success, message).
    """
    try:
        image = Image.open(path)
    except Exception as exc:
        return False, f'Cannot open image: {exc}'

    backup_path = ''
    if backup:
        backup_path = path.with_suffix(f'.backup{path.suffix}')
        shutil.copy2(path, backup_path)

    # piexif: zero out all EXIF IFDs then insert a clean empty block
    try:
        exif_bytes = piexif.dump({ # type: ignore
            '0th': {},
            'Exif': {},
            'GPS': {},
            '1st': {},
        })
        image.save(path, exif=exif_bytes)
        msg = f'EXIF stripped.{f"  Backup saved to: {backup_path}" if backup else ""}'
        return True, msg
    except (struct.error, ValueError, piexif.InvalidImageDataError):
        # Some formats (PNG, etc.) don't support piexif — save without it
        try:
            data = list(image.getdata()) # type: ignore
            clean = Image.new(image.mode, image.size)
            clean.putdata(data) # type: ignore[arg-type]
            clean.save(path)
            msg = (f'EXIF stripped (format fallback).'
                   f'{f"  Backup: {backup_path}" if backup else ""}')
            return True, msg
        except Exception as exc2:
            return False, f'Strip failed: {exc2}'
        
def _degrees_to_rational(value: float) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Convert decimal degrees to EXIF rational tuple."""
    d = int(abs(value))
    m = int((abs(value) - d) * 60)
    s = (abs(value) - d - m / 60) * 3600
    return ((d, 1), (m, 1), (int(s * 1000), 1000))

def _apply_updates(
    exif_dict: dict[str, dict[int, Any]], updates: dict[str, str]) -> tuple[dict[str, dict[int, Any]], list[str]]:
    """Apply string updates into an exif_dict, returning the modified dict and any errors."""
    errors: list[str] = []

    for field_name, raw in updates.items():
        if field_name == 'GPS':
            try:
                parts = raw.split(',')
                lat = float(parts[0].strip())
                lon = float(parts[1].strip())
            except (ValueError, IndexError):
                errors.append('GPS: invalid format, expected "lat,lon"')
                continue
            lat_ref = b'N' if lat >= 0 else b'S'
            lon_ref = b'E' if lon >= 0 else b'W'
            exif_dict['GPS'].update({
                piexif.GPSIFD.GPSLatitude: _degrees_to_rational(lat), # type: ignore[attr-defined]
                piexif.GPSIFD.GPSLatitudeRef: lat_ref, # type: ignore[attr-defined]
                piexif.GPSIFD.GPSLongitude: _degrees_to_rational(lon), # type: ignore[attr-defined]
                piexif.GPSIFD.GPSLongitudeRef: lon_ref, # type: ignore[attr-defined]
            })
            continue

        if field_name == 'UserComment':
            encoded = b'ASCII\x00\x00\x00' + raw.encode('utf-8')
            ifd, tag_id = FIELD_IFD_MAP['UserComment']
            exif_dict[ifd][tag_id] = encoded
            continue

        if field_name == 'DateTime':
            normalised = raw.replace('-', ':') if raw.count('-') >= 2 else raw
            ifd, tag_id = FIELD_IFD_MAP['DateTime']
            exif_dict[ifd][tag_id] = normalised.encode('utf-8')
            continue

        entry = FIELD_IFD_MAP.get(field_name)
        if entry is None:
            errors.append(f'{field_name}: unknown field, skipped')
            continue
        ifd, tag_id = entry
        exif_dict[ifd][tag_id] = raw.encode('utf-8')

    return exif_dict, errors

def write_exif(path: Path, updates: dict[str, str], wipe: bool = False) -> tuple[bool, str]:
    try:
        image = Image.open(path)
    except Exception as exc:
        return False, f'Cannot open image: {exc}'

    fmt = image.format or ''
    piexif_formats = {'JPEG', 'TIFF'}

    if fmt not in piexif_formats:
        # Pillow-only path: load existing via Pillow, merge, save back
        if wipe:
            exif_bytes = b''
        else:
            existing_exif = image.info.get('exif', b'')
            if existing_exif:
                try:
                    existing = piexif.load(existing_exif) # type: ignore[no-untyped-call]
                    exif_dict: dict[str, dict[int, Any]] = {
                        '0th': dict(existing.get('0th', {})), # type: ignore[union-attr]
                        'Exif': dict(existing.get('Exif', {})), # type: ignore[union-attr]
                        'GPS': dict(existing.get('GPS', {})), # type: ignore[union-attr]
                        '1st': dict(existing.get('1st', {})), # type: ignore[union-attr]
                    }
                except Exception:
                    exif_dict = {'0th': {}, 'Exif': {}, 'GPS': {}, '1st': {}}
            else:
                exif_dict = {'0th': {}, 'Exif': {}, 'GPS': {}, '1st': {}}

            exif_dict, errors = _apply_updates(exif_dict, updates)
            try:
                exif_bytes = piexif.dump(exif_dict) # type: ignore[no-untyped-call]
            except Exception as exc:
                return False, f'Failed to build EXIF block: {exc}'

        try:
            if exif_bytes:
                image.save(path, exif=exif_bytes)
            else:
                image.save(path)
            return True, 'EXIF written.'
        except Exception as exc:
            return False, f'Failed to save image: {exc}'

    # JPEG / TIFF path via piexif
    if wipe:
        exif_dict = {'0th': {}, 'Exif': {}, 'GPS': {}, '1st': {}}
    else:
        try:
            existing = piexif.load(str(path)) # type: ignore[no-untyped-call]
            exif_dict = {
                '0th':  dict(existing.get('0th', {})), # type: ignore[union-attr]
                'Exif': dict(existing.get('Exif', {})), # type: ignore[union-attr]
                'GPS':  dict(existing.get('GPS', {})), # type: ignore[union-attr]
                '1st':  dict(existing.get('1st', {})), # type: ignore[union-attr]
            }
        except Exception as exc:
            print(f'  {DIM}Warning: could not load existing EXIF ({exc}), starting fresh{RESET}')
            exif_dict = {'0th': {}, 'Exif': {}, 'GPS': {}, '1st': {}}

    exif_dict, errors = _apply_updates(exif_dict, updates)

    try:
        new_bytes: bytes = piexif.dump(exif_dict) # type: ignore[no-untyped-call]
        image.save(path, exif=new_bytes)
    except Exception as exc:
        return False, f'Failed to write EXIF: {exc}'

    msg = 'EXIF written.'
    if errors:
        msg += '  Warnings: ' + '; '.join(errors)
    return True, msg


# Display helpers
RESET = '\033[0m'
BOLD = '\033[1m'
CYAN = '\033[36m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
RED = '\033[31m'
DIM = '\033[2m'

COL_WIDTH = 32  # tag column width

FIELD_IFD_MAP: dict[str, tuple[str, int]] = {
    'DateTime': ('0th', piexif.ImageIFD.DateTime), # type: ignore[attr-defined]
    'ImageDescription': ('0th', piexif.ImageIFD.ImageDescription), # type: ignore[attr-defined]
    'Artist': ('0th', piexif.ImageIFD.Artist), # type: ignore[attr-defined]
    'Copyright': ('0th', piexif.ImageIFD.Copyright), # type: ignore[attr-defined]
    'Make': ('0th', piexif.ImageIFD.Make), # type: ignore[attr-defined]
    'Model': ('0th', piexif.ImageIFD.Model), # type: ignore[attr-defined]
    'Software': ('0th', piexif.ImageIFD.Software), # type: ignore[attr-defined]
    'UserComment': ('Exif', piexif.ExifIFD.UserComment), # type: ignore[attr-defined]
    'GPS': ('GPS', -1), # handled separately
}

WRITABLE_FIELDS: dict[str, str] = {
    '1': 'DateTime',
    '2': 'ImageDescription',
    '3': 'Artist',
    '4': 'Copyright',
    '5': 'Make',
    '6': 'Model',
    '7': 'Software',
    '8': 'UserComment',
    '9': 'GPS',
}


def print_report(report: ExifReport) -> None:
    print()
    print(f'{BOLD}{"─" * 60}{RESET}')
    print(f'{BOLD}{CYAN}  {report.path}{RESET}')
    print(f'{BOLD}{"─" * 60}{RESET}')

    if report.error:
        print(f'  {RED}Error:{RESET} {report.error}')
        return

    if not report.has_exif:
        print(f'  {YELLOW}No EXIF data found in this file.{RESET}')
        return

    print(f'  {DIM}{len(report.fields)} fields found{RESET}\n')

    for f in report.fields:
        tag_col = f.tag.ljust(COL_WIDTH)
        print(f'  {CYAN}{tag_col}{RESET}  {f.display_value}')


def prompt_strip(report: ExifReport) -> None:
    """Ask the user whether to strip EXIF from this file."""
    if not report.has_exif:
        return

    print()
    try:
        answer = input(f'  Strip EXIF from {report.path.name}? [y/N/b=strip without backup]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if answer == 'y':
        ok, msg = strip_exif(report.path, backup=True)
    elif answer == 'b':
        ok, msg = strip_exif(report.path, backup=False)
    else:
        print(f'  {DIM}Skipped.{RESET}')
        return

    colour = GREEN if ok else RED
    print(f'  {colour}{msg}{RESET}')

def prompt_add_exif(path: Path) -> None:
    """Prompt the user to add or overwrite EXIF fields."""
    try:
        answer = input(f'  Add/edit EXIF fields on {path.name}? [y/N]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if answer != 'y':
        print(f'  {DIM}Skipped.{RESET}')
        return
    
    try:
        mode = input('  Merge into existing EXIF, or wipe and rewrite? [M/w]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    wipe = mode == 'w'

    updates: dict[str, str] = {}

    while True:
        print()
        for key, name in WRITABLE_FIELDS.items():
            hint = ' (format: lat,lon e.g. 51.5074,-0.1278)' if name == 'GPS' else \
                   ' (format: YYYY-MM-DD HH:MM:SS)' if name == 'DateTime' else ''
            print(f'    {CYAN}{key}{RESET}  {name}{DIM}{hint}{RESET}')
        print(f'    {CYAN}d{RESET}  Done')
        print()

        try:
            choice = input('  Field to set: ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == 'd':
            break

        field_name = WRITABLE_FIELDS.get(choice)
        if field_name is None:
            print(f'  {YELLOW}Invalid choice.{RESET}')
            continue

        hint = ' (lat,lon)' if field_name == 'GPS' else \
               ' (YYYY-MM-DD HH:MM:SS)' if field_name == 'DateTime' else ''
        try:
            value = input(f'  {field_name}{hint}: ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if value:
            updates[field_name] = value
            print(f'  {DIM}Queued: {field_name} = {value}{RESET}')

    if not updates:
        print(f'  {DIM}No changes queued.{RESET}')
        return

    ok, msg = write_exif(path, updates, wipe=wipe)
    colour = GREEN if ok else RED
    print(f'  {colour}{msg}{RESET}')


# Entry point
def collect_paths_interactive() -> list[Path]:
    """Prompt the user for file paths until they enter a blank line."""
    print(f'{BOLD}EXIF Tool{RESET} — enter image paths one per line, blank line to finish.\n')
    paths: list[Path] = []
    while True:
        try:
            raw = input('  Image path: ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw:
            break
        paths.append(Path(raw))
    return paths


def main() -> None:
    if len(sys.argv) > 1:
        paths = [Path(p) for p in sys.argv[1:]]
    else:
        paths = collect_paths_interactive()

    if not paths:
        print('No files provided. Exiting.')
        sys.exit(0)

    reports = [read_exif(p) for p in paths]

    for report in reports:
        print_report(report)
        prompt_strip(report)
        prompt_add_exif(report.path)

    print()


if __name__ == '__main__':
    main()