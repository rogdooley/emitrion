"""Single-byte XOR payload encoder with self-decoding stub.

Transforms an assembled shellcode payload so that the final byte stream
(decoder stub + encoded body) contains no forbidden bytes.

The decoder stub runs first, XOR-decodes the body in place, then falls
through to the now-clean payload.

Usage::

    from emitera.xor_encoder import xor_encode

    result = xor_encode(raw_shellcode, badchars={0x00, 0x0a, 0x0d})
    if result.success:
        final = result.encoded   # decoder_stub || encoded_payload
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EncoderResult:
    success: bool
    strategy: str = "xor8"
    encoded: bytes | None = None
    key: int | None = None
    stub_size: int = 0
    payload_size: int = 0
    keys_tested: int = 0
    payload_clean_keys: int = 0
    diagnostics: str = ""


# -- Decoder stub builder ----------------------------------------------
#
# Stub layout (small, payload <= 255):
#
#   [pad]               optional neutral padding (shifts jmp disp)
#   EB [jmp1]           jmp short call_tag
#   5E                  pop esi                 ; decoder:
#   31 C9               xor ecx, ecx
#   B1 [LEN]            mov cl, payload_len
#   [pad]               optional neutral padding (shifts loop/call disps)
#   80 36 [KEY]         xor byte [esi], KEY     ; decode_loop:
#   46                  inc esi
#   E2 [loop]           loop decode_loop
#   EB 05               jmp short payload
#   E8 [c0 c1 c2 c3]   call decoder            ; call_tag:
#                       encoded payload starts here
#
# Large stub (payload 256-65535): uses 66 B9 [lo] [hi] instead of B1 [len].
#
# The padding approach: inserting 1-byte neutral instructions shifts
# displacement values to dodge badchar collisions.  Up to 16 padding
# bytes are tried in two insertion points.

# Single-byte neutral instructions that don't alter program state
_NEUTRAL_CANDIDATES = [
    0x90,  # nop
    0xFC,  # cld
    0xF8,  # clc
    0xF9,  # stc
    0xF5,  # cmc
]


def _pick_neutral(badchars: set[int]) -> int | None:
    for b in _NEUTRAL_CANDIDATES:
        if b not in badchars:
            return b
    return None


def _build_stub(
    payload_len: int,
    key: int,
    badchars: set[int],
    pre_pad: int = 0,
    mid_pad: int = 0,
    neutral: int = 0x90,
) -> bytes | None:
    """Try to build a decoder stub with given padding amounts.

    Returns the complete stub bytes if all bytes are clean, None otherwise.
    pre_pad:  neutral bytes inserted before the jmp (shifts jmp displacement)
    mid_pad:  neutral bytes inserted between mov-cl and the xor-loop
              (shifts loop displacement and first-jmp displacement)
    """
    small = payload_len <= 255

    # Build the instruction stream
    parts: list[int] = []

    # -- pre-padding (before the jmp short)
    parts.extend([neutral] * pre_pad)

    # -- jmp short call_tag (placeholder displacement)
    jmp1_idx = len(parts)
    parts.extend([0xEB, 0x00])

    # -- decoder: pop esi
    decoder_offset = len(parts)
    parts.append(0x5E)

    # -- xor ecx, ecx
    parts.extend([0x31, 0xC9])

    # -- mov cl/cx, payload_len
    if small:
        parts.extend([0xB1, payload_len & 0xFF])
    else:
        lo = payload_len & 0xFF
        hi = (payload_len >> 8) & 0xFF
        parts.extend([0x66, 0xB9, lo, hi])

    # -- mid-padding
    parts.extend([neutral] * mid_pad)

    # -- decode_loop: xor byte [esi], key
    loop_target = len(parts)
    parts.extend([0x80, 0x36, key])

    # -- inc esi
    parts.append(0x46)

    # -- loop decode_loop
    loop_instr = len(parts)
    loop_disp = loop_target - (loop_instr + 2)
    parts.extend([0xE2, loop_disp & 0xFF])

    # -- jmp short payload (skip over the 5-byte call)
    parts.extend([0xEB, 0x05])

    # -- call_tag: call decoder
    call_instr = len(parts)
    call_next = call_instr + 5
    call_disp = decoder_offset - call_next
    call_bytes = call_disp & 0xFFFFFFFF
    parts.append(0xE8)
    parts.extend([(call_bytes >> (8 * i)) & 0xFF for i in range(4)])

    # -- fix jmp1 displacement
    jmp1_next = jmp1_idx + 2
    jmp1_target = call_instr
    jmp1_disp = jmp1_target - jmp1_next
    parts[jmp1_idx + 1] = jmp1_disp & 0xFF

    stub = bytes(parts)

    # Validate: no badchar in the stub
    for i, b in enumerate(stub):
        if b in badchars:
            return None

    return stub


def _build_fnstenv_stub(
    payload_len: int,
    key: int,
    badchars: set[int],
    pad: int = 0,
    neutral: int = 0x90,
) -> bytes | None:
    """Build a decoder stub using fldz/fnstenv to get EIP (no call/0xFF).

    Layout:
      D9 EE              fldz
      D9 74 24 F4        fnstenv [esp-0x0c]
      5E                 pop esi          ; ESI = &fldz
      [pad]              optional padding
      83 C6 [OFF]        add esi, offset  ; ESI = &payload
      31 C9              xor ecx, ecx
      B1/66B9 [LEN]      mov cl/cx, len
      56                 push esi         ; save for ret
      80 36 [KEY]        xor byte [esi], key
      46                 inc esi
      E2 [DISP]          loop
      C3                 ret              ; jump to decoded payload
    """
    small = payload_len <= 255

    parts: list[int] = []

    # fldz
    parts.extend([0xD9, 0xEE])
    # fnstenv [esp-0x0c]
    parts.extend([0xD9, 0x74, 0x24, 0xF4])
    # pop esi
    parts.append(0x5E)

    # optional padding
    parts.extend([neutral] * pad)

    # add esi, <stub_size> - placeholder, fix after computing total
    add_idx = len(parts)
    parts.extend([0x83, 0xC6, 0x00])

    # xor ecx, ecx
    parts.extend([0x31, 0xC9])

    # mov cl/cx, len
    if small:
        parts.extend([0xB1, payload_len & 0xFF])
    else:
        lo = payload_len & 0xFF
        hi = (payload_len >> 8) & 0xFF
        parts.extend([0x66, 0xB9, lo, hi])

    # push esi
    parts.append(0x56)

    # decode_loop
    loop_target = len(parts)
    parts.extend([0x80, 0x36, key])

    # inc esi
    parts.append(0x46)

    # loop
    loop_instr = len(parts)
    loop_disp = loop_target - (loop_instr + 2)
    parts.extend([0xE2, loop_disp & 0xFF])

    # ret
    parts.append(0xC3)

    # Fix the add offset - distance from fldz to end of stub
    stub_size = len(parts)
    parts[add_idx + 2] = stub_size & 0xFF

    stub = bytes(parts)

    for b in stub:
        if b in badchars:
            return None
    return stub


def _try_build_stub(
    payload_len: int,
    key: int,
    badchars: set[int],
) -> bytes | None:
    """Try multiple stub variants and padding to find a clean stub."""
    neutral = _pick_neutral(badchars)
    if neutral is None:
        return None

    # Try call-based stub first (smaller)
    for pre in range(9):
        for mid in range(9):
            stub = _build_stub(payload_len, key, badchars, pre, mid, neutral)
            if stub is not None:
                return stub

    # Try fnstenv-based stub (avoids 0xFF from call displacement)
    for pad in range(9):
        stub = _build_fnstenv_stub(payload_len, key, badchars, pad, neutral)
        if stub is not None:
            return stub

    return None


def _check_length_bytes(payload_len: int, badchars: set[int]) -> str | None:
    """Check if the payload length can be encoded without badchars."""
    if payload_len <= 255:
        if payload_len in badchars:
            return (
                f"Payload length {payload_len} (0x{payload_len:02x}) "
                f"is itself a forbidden byte."
            )
    else:
        lo = payload_len & 0xFF
        hi = (payload_len >> 8) & 0xFF
        if lo in badchars or hi in badchars:
            return (
                f"Payload length {payload_len} (0x{payload_len:04x}) "
                f"encodes as bytes 0x{lo:02x} 0x{hi:02x}, "
                f"one of which is forbidden."
            )
    return None


def xor_encode(payload: bytes, badchars: set[int]) -> EncoderResult:
    """Encode *payload* with single-byte XOR to eliminate *badchars*.

    Tries every key 1-255, skipping keys that are themselves forbidden.
    For each candidate key, checks that the encoded payload AND the
    complete decoder stub (with key and length substituted) are free of
    forbidden bytes.

    Returns an EncoderResult with diagnostics regardless of success.
    """
    plen = len(payload)
    if plen == 0:
        return EncoderResult(
            success=True,
            encoded=b"",
            key=None,
            payload_size=0,
            diagnostics="Empty payload - nothing to encode.",
        )

    if plen > 65535:
        return EncoderResult(
            success=False,
            payload_size=plen,
            diagnostics=f"Payload too large for XOR8 encoder ({plen} bytes, max 65535).",
        )

    # Check if a neutral padding byte exists
    neutral = _pick_neutral(badchars)
    if neutral is None:
        return EncoderResult(
            success=False,
            payload_size=plen,
            diagnostics=(
                "No neutral padding byte available - all NOP-like instructions "
                "are forbidden. A more advanced encoder is needed."
            ),
        )

    # Check length encoding
    len_err = _check_length_bytes(plen, badchars)
    if len_err:
        return EncoderResult(
            success=False,
            payload_size=plen,
            diagnostics=f"{len_err}\nPad the payload or use a different encoder.",
        )

    keys_tested = 0
    payload_clean_keys = 0
    stub_failure_detail: str | None = None

    for key in range(1, 256):
        if key in badchars:
            continue
        keys_tested += 1

        # Encode the payload body
        encoded_body = bytes(b ^ key for b in payload)

        # Check encoded payload for badchars
        if any(b in badchars for b in encoded_body):
            continue

        payload_clean_keys += 1

        # Try to build a clean decoder stub
        stub = _try_build_stub(plen, key, badchars)
        if stub is None:
            if stub_failure_detail is None:
                stub_failure_detail = (
                    f"Key 0x{key:02x}: encoded payload clean, "
                    f"but no valid decoder stub found."
                )
            continue

        full = stub + encoded_body

        # Final sanity check
        if any(b in badchars for b in full):
            continue

        diag_lines = [
            "Encoding Strategy  XOR8",
            f"Forbidden          {' '.join(f'{b:02x}' for b in sorted(badchars))}",
            f"Key                0x{key:02x}",
            f"Payload            {plen} bytes",
            f"Stub               {len(stub)} bytes",
            f"Total              {len(full)} bytes",
            f"Keys Tested        {keys_tested}",
            f"Payload-Clean Keys {payload_clean_keys}",
            "Result             SUCCESS",
        ]
        return EncoderResult(
            success=True,
            encoded=full,
            key=key,
            stub_size=len(stub),
            payload_size=plen,
            keys_tested=keys_tested,
            payload_clean_keys=payload_clean_keys,
            diagnostics="\n".join(diag_lines),
        )

    # No valid key found
    diag_lines = [
        "Encoding Strategy  XOR8",
        f"Forbidden          {' '.join(f'{b:02x}' for b in sorted(badchars))}",
        f"Payload            {plen} bytes",
        f"Keys Tested        {keys_tested}",
        f"Payload-Clean Keys {payload_clean_keys}",
        "Result             FAILURE",
    ]
    if stub_failure_detail:
        diag_lines.append("")
        diag_lines.append(stub_failure_detail)
    return EncoderResult(
        success=False,
        payload_size=plen,
        keys_tested=keys_tested,
        payload_clean_keys=payload_clean_keys,
        diagnostics="\n".join(diag_lines),
    )
