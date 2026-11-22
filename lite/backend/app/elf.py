"""Strict parser for the narrow ELF profile accepted by VulnGenome Lite."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass


class ELFValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ELFInfo:
    file_format: str
    architecture: str
    endianness: str
    object_type: str
    os_abi: int
    entry_point: int
    program_headers: int
    load_segments: int
    dynamic_segment: bool
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_elf64_amd64_shared_object(data: bytes) -> ELFInfo:
    """Validate ELF64 little-endian x86-64 ET_DYN bounds without loading it."""
    if len(data) < 64:
        raise ELFValidationError("File is shorter than an ELF64 header")
    if data[:4] != b"\x7fELF":
        raise ELFValidationError("File does not have an ELF identification header")
    ident = data[:16]
    if ident[4] != 2:
        raise ELFValidationError("Only ELF64 (EI_CLASS=2) is supported")
    if ident[5] != 1:
        raise ELFValidationError("Only little-endian ELF (EI_DATA=1) is supported")
    if ident[6] != 1:
        raise ELFValidationError("Unsupported ELF identification version")
    if ident[7] not in (0, 3):
        raise ELFValidationError("Only System V/Linux ELF OS ABI values are supported")

    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, _flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHIQQQIHHHHHH", data, 16
    )
    if e_type != 3:
        raise ELFValidationError("Only ET_DYN shared-object profile inputs are supported")
    if e_machine != 62:
        raise ELFValidationError("Only AMD64/x86-64 ELF (e_machine=62) is supported")
    if e_version != 1 or e_ehsize != 64:
        raise ELFValidationError("Invalid or unsupported ELF64 header version/size")
    if e_phnum in (0, 0xFFFF) or e_phentsize != 56:
        raise ELFValidationError("A bounded, non-extended ELF64 program-header table is required")
    if e_phoff < 64 or e_phoff + e_phnum * e_phentsize > len(data):
        raise ELFValidationError("ELF program-header table extends beyond the uploaded file")

    if e_shnum == 0:
        if e_shoff != 0:
            raise ELFValidationError("Extended ELF section counts are not supported by this profile")
        if e_shstrndx not in (0, 0xFFFF):
            raise ELFValidationError("Invalid section-name index for an ELF without sections")
    else:
        if e_shnum == 0xFFFF or e_shentsize != 64:
            raise ELFValidationError("Extended or nonstandard ELF section tables are unsupported")
        if e_shoff < 64 or e_shoff + e_shnum * e_shentsize > len(data):
            raise ELFValidationError("ELF section-header table extends beyond the uploaded file")
        if e_shstrndx != 0xFFFF and e_shstrndx >= e_shnum:
            raise ELFValidationError("ELF section-name index is out of range")
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            (_name, section_type, _flags, _address, section_offset, section_size,
             _link, _info, _alignment, _entry_size) = struct.unpack_from("<IIQQQQIIQQ", data, offset)
            if section_type != 8 and section_offset + section_size > len(data):  # SHT_NOBITS has no file payload.
                raise ELFValidationError(f"ELF section {index} extends beyond the uploaded file")

    load_segments = 0
    dynamic_segment = False
    interpreter_segment = False
    dynamic_payload: tuple[int, int] | None = None
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_offset + p_filesz > len(data):
            raise ELFValidationError(f"ELF program segment {index} extends beyond the uploaded file")
        if p_type == 1:  # PT_LOAD
            load_segments += 1
            if p_filesz > p_memsz:
                raise ELFValidationError(f"ELF load segment {index} has filesz greater than memsz")
            if p_align not in (0, 1) and (p_align & (p_align - 1)):
                raise ELFValidationError(f"ELF load segment {index} has invalid alignment")
            if p_align > 1 and p_vaddr % p_align != p_offset % p_align:
                raise ELFValidationError(f"ELF load segment {index} violates alignment congruence")
        elif p_type == 2:  # PT_DYNAMIC
            dynamic_segment = True
            dynamic_payload = (p_offset, p_filesz)
        elif p_type == 3:  # PT_INTERP
            interpreter_segment = True

    if not load_segments or not dynamic_segment:
        raise ELFValidationError("Input must be a dynamically linked ELF shared object with a PT_LOAD and PT_DYNAMIC segment")
    if dynamic_payload is None or dynamic_payload[1] < 16 or dynamic_payload[1] % 16:
        raise ELFValidationError("ELF PT_DYNAMIC must contain complete ELF64 dynamic entries")
    dynamic_offset, dynamic_size = dynamic_payload
    dynamic_tags = [struct.unpack_from("<qQ", data, offset)[0]
                    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16)]
    if 0 not in dynamic_tags:
        raise ELFValidationError("ELF PT_DYNAMIC has no bounded DT_NULL terminator")
    if interpreter_segment:
        raise ELFValidationError("ELF contains PT_INTERP and is outside the shared-object profile")

    return ELFInfo(
        file_format="ELF64",
        architecture="x86-64",
        endianness="little",
        object_type="ET_DYN shared object",
        os_abi=ident[7],
        entry_point=e_entry,
        program_headers=e_phnum,
        load_segments=load_segments,
        dynamic_segment=dynamic_segment,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
