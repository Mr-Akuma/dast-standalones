"""
EXIF Scanner — detects sensitive metadata in image responses.
Equivalent to ZAP's Image Location and Privacy Scanner add-on.

Parses JPEG EXIF metadata using pure Python (stdlib struct only, no Pillow).
Detects GPS coordinates, camera make/model, software, author/creator fields.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class ExifFinding:
    url: str
    finding: str
    severity: str
    evidence: str
    metadata_type: str
    raw_value: str
    cwe: str
    agent_id: str = "exif_scanner"
    icon: str = "\U0001f4f7"

    def to_dict(self) -> dict:
        return asdict(self)


class ExifScanner:
    """Parses JPEG EXIF data and flags privacy-sensitive metadata."""

    _IMAGE_CONTENT_TYPES = {"image/jpeg", "image/jpg", "image/pjpeg"}  # Only JPEG has reliable EXIF

    _EXIF_TAG_NAMES = {
        0x010F: "Make",
        0x0110: "Model",
        0x0131: "Software",
        0x013B: "Artist",
        0x8298: "Copyright",
        0x9003: "DateTimeOriginal",
        0x9C9B: "XPAuthor",
        0x013C: "HostComputer",
        0x8825: "GPSInfoIFDPointer",  # GPS sub-IFD
    }

    _GPS_TAG_NAMES = {
        0x0001: "GPSLatitudeRef",
        0x0002: "GPSLatitude",
        0x0003: "GPSLongitudeRef",
        0x0004: "GPSLongitude",
        0x001D: "GPSDateStamp",
        0x001C: "GPSAreaInformation",
    }

    # TIFF type sizes: type_id -> (format_char, byte_size)
    _TIFF_TYPES = {
        1: ("B", 1),   # BYTE
        2: ("s", 1),   # ASCII
        3: ("H", 2),   # SHORT
        4: ("I", 4),   # LONG
        5: ("I", 4),   # RATIONAL (two LONGs = 8 bytes, handled specially)
        7: ("B", 1),   # UNDEFINED
        9: ("i", 4),   # SLONG
        10: ("i", 4),  # SRATIONAL
    }

    @staticmethod
    def _is_jpeg(data: bytes) -> bool:
        """Check JPEG magic bytes FF D8 FF."""
        return len(data) >= 3 and data[0:3] == b"\xff\xd8\xff"

    @classmethod
    def _parse_ifd(cls, data: bytes, offset: int, byte_order: str, depth: int = 0) -> dict:
        """Parse an IFD (Image File Directory) at given offset.

        Args:
            data: Raw TIFF data (starting from TIFF header).
            offset: Byte offset to the IFD.
            byte_order: '>' for big-endian (Motorola), '<' for little-endian (Intel).
            depth: Recursion depth guard.

        Returns:
            Dict of {tag_id: value}.
        """
        if depth > 4:
            return {}
        try:
            entry_count = struct.unpack_from(f"{byte_order}H", data, offset)[0]
        except (struct.error, IndexError):
            return {}

        tags: dict = {}
        for i in range(entry_count):
            entry_offset = offset + 2 + i * 12
            try:
                tag_id, type_id, count, value_offset_raw = struct.unpack_from(
                    f"{byte_order}HHI4s", data, entry_offset
                )
            except (struct.error, IndexError):
                continue

            try:
                value = cls._read_tag_value(data, byte_order, type_id, count, value_offset_raw)
            except Exception:
                continue

            tags[tag_id] = value

        return tags

    @classmethod
    def _read_tag_value(cls, data: bytes, byte_order: str, type_id: int, count: int, value_offset_raw: bytes):
        """Extract a tag value from raw IFD entry data."""
        type_info = cls._TIFF_TYPES.get(type_id)
        if type_info is None:
            return None

        _, unit_size = type_info

        # RATIONAL / SRATIONAL are two ints = 8 bytes per value
        if type_id in (5, 10):
            total_size = count * 8
        else:
            total_size = count * unit_size

        # If total fits in 4 bytes, value is inline; otherwise it's an offset
        if total_size <= 4:
            raw = value_offset_raw[:total_size]
        else:
            val_offset = struct.unpack_from(f"{byte_order}I", value_offset_raw, 0)[0]
            raw = data[val_offset: val_offset + total_size]

        # ASCII string
        if type_id == 2:
            return raw.rstrip(b"\x00").decode("ascii", errors="replace")

        # SHORT
        if type_id == 3:
            values = struct.unpack(f"{byte_order}{count}H", raw)
            return values[0] if count == 1 else values

        # LONG
        if type_id == 4:
            values = struct.unpack(f"{byte_order}{count}I", raw)
            return values[0] if count == 1 else values

        # RATIONAL — pair of LONGs
        if type_id == 5:
            rationals = []
            for j in range(count):
                num, den = struct.unpack_from(f"{byte_order}II", raw, j * 8)
                rationals.append((num, den))
            return rationals[0] if count == 1 else rationals

        # SRATIONAL
        if type_id == 10:
            rationals = []
            for j in range(count):
                num, den = struct.unpack_from(f"{byte_order}ii", raw, j * 8)
                rationals.append((num, den))
            return rationals[0] if count == 1 else rationals

        # Fallback for BYTE / UNDEFINED
        return raw

    @classmethod
    def _parse_exif(cls, data: bytes) -> dict:
        """Scan JPEG APP1 markers for EXIF data and return named tags.

        Returns:
            Dict of {tag_name: value} for recognized tags.
        """
        if not cls._is_jpeg(data):
            return {}

        pos = 2  # skip SOI
        while pos < len(data) - 4:
            # Find next marker
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            # SOS or EOI — stop scanning
            if marker in (0xDA, 0xD9):
                break
            seg_length = struct.unpack_from(">H", data, pos + 2)[0]
            seg_data = data[pos + 4: pos + 2 + seg_length]

            # APP1 marker = 0xE1
            if marker == 0xE1 and seg_data[:6] == b"Exif\x00\x00":
                tiff_data = seg_data[6:]
                return cls._decode_tiff(tiff_data)

            pos += 2 + seg_length

        return {}

    @classmethod
    def _decode_tiff(cls, tiff_data: bytes) -> dict:
        """Decode TIFF header and IFD entries."""
        if len(tiff_data) < 8:
            return {}

        # Byte order
        bo_marker = tiff_data[0:2]
        if bo_marker == b"II":
            byte_order = "<"
        elif bo_marker == b"MM":
            byte_order = ">"
        else:
            return {}

        # Verify TIFF magic (42)
        try:
            magic = struct.unpack_from(f"{byte_order}H", tiff_data, 2)[0]
        except struct.error:
            return {}
        if magic != 42:
            return {}

        ifd0_offset = struct.unpack_from(f"{byte_order}I", tiff_data, 4)[0]
        raw_tags = cls._parse_ifd(tiff_data, ifd0_offset, byte_order)

        result: dict = {}
        gps_offset: Optional[int] = None

        for tag_id, value in raw_tags.items():
            name = cls._EXIF_TAG_NAMES.get(tag_id)
            if name == "GPSInfoIFDPointer":
                gps_offset = value
            elif name:
                result[name] = value

        # Parse GPS sub-IFD
        if gps_offset is not None:
            gps_tags = cls._parse_ifd(tiff_data, gps_offset, byte_order, depth=1)
            for tag_id, value in gps_tags.items():
                name = cls._GPS_TAG_NAMES.get(tag_id)
                if name:
                    result[name] = value

        return result

    def detect_image(self, response) -> bool:
        """Return True if the response Content-Type indicates a JPEG image."""
        ct = getattr(response, "headers", {}).get("Content-Type", "")
        ct_lower = ct.lower().split(";")[0].strip()
        return ct_lower in self._IMAGE_CONTENT_TYPES

    def scan(self, url: str, response) -> list[ExifFinding]:
        """Scan a JPEG HTTP response for sensitive EXIF metadata.

        Args:
            url: The URL the image was fetched from.
            response: An HTTP response object with .headers and .content attributes.

        Returns:
            List of ExifFinding for each sensitive metadata field detected.
        """
        if not self.detect_image(response):
            return []

        content = getattr(response, "content", b"")
        if not content:
            return []

        tags = self._parse_exif(content)
        if not tags:
            return []

        findings: list[ExifFinding] = []

        # GPS coordinates
        if "GPSLatitude" in tags and "GPSLongitude" in tags:
            lat = tags["GPSLatitude"]
            lon = tags["GPSLongitude"]
            lat_ref = tags.get("GPSLatitudeRef", "N")
            lon_ref = tags.get("GPSLongitudeRef", "E")
            evidence = f"GPS: {lat_ref} {lat}, {lon_ref} {lon}"
            findings.append(ExifFinding(
                url=url,
                finding="GPS coordinates embedded in image EXIF data",
                severity="Critical",
                evidence=evidence,
                metadata_type="GPS",
                raw_value=evidence,
                cwe="CWE-200",
            ))

        # Camera make/model
        make = tags.get("Make")
        model = tags.get("Model")
        if make or model:
            parts = [p for p in (make, model) if p]
            evidence = "Camera: " + " ".join(str(p) for p in parts)
            findings.append(ExifFinding(
                url=url,
                finding="Camera make/model in EXIF metadata",
                severity="Low",
                evidence=evidence,
                metadata_type="CameraMakeModel",
                raw_value=evidence,
                cwe="CWE-200",
            ))

        # Author / creator fields
        for tag_name in ("Artist", "Copyright", "XPAuthor"):
            val = tags.get(tag_name)
            if val:
                evidence = f"{tag_name}: {val}"
                findings.append(ExifFinding(
                    url=url,
                    finding="Author/creator metadata in EXIF data",
                    severity="Medium",
                    evidence=evidence,
                    metadata_type="AuthorCreator",
                    raw_value=str(val),
                    cwe="CWE-200",
                ))

        # Software
        software = tags.get("Software")
        if software:
            evidence = f"Software: {software}"
            findings.append(ExifFinding(
                url=url,
                finding="Software version in EXIF metadata",
                severity="Low",
                evidence=evidence,
                metadata_type="Software",
                raw_value=str(software),
                cwe="CWE-200",
            ))

        return findings
