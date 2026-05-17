from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import md5
import logging
import os
from typing import Final

from bleak import BleakClient
from bleak.exc import BleakError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

from .const import (
    BLE_COMMAND_TIMEOUT,
    BLE_CONNECT_TIMEOUT,
    LOCAL_AES_KEY,
    MODBUS_READ_FUNCTION,
    MODBUS_SLAVE_ADDRESS,
    NOTIFY_CHAR_UUID,
    PRIVATE_KEY_L1,
    PUBLIC_KEY_K2,
    REG_APP_HOME_DATA,
    REG_BASE_CONFIG,
    REG_BASE_CONFIG_LEN,
    WRITE_CHAR_UUID,
    WRITE_CHUNK_DELAY,
    WRITE_CHUNK_SIZE,
)

_LOGGER = logging.getLogger(__name__)

_HANDSHAKE_PREFIX: Final = b"\x2A\x2A"
_STATIC_PUBLIC_KEY: Final = serialization.load_der_public_key(bytes.fromhex(PUBLIC_KEY_K2))
_STATIC_PRIVATE_KEY: Final = ec.derive_private_key(int(PRIVATE_KEY_L1, 16), ec.SECP256R1())


class BluettiBleError(Exception):
    """Raised when the Bluetti BLE protocol fails."""


@dataclass(slots=True)
class BluettiHomeData:
    protocol_version: int
    model: str
    battery_voltage: float
    battery_current: float
    battery_soc: int
    dc_output_power: int
    ac_output_power: int
    pv_input_power: int
    grid_power: int
    inverter_power: int


class BluettiBleClient:
    def __init__(self, hass: HomeAssistant, address: str, encrypted: bool) -> None:
        self._hass = hass
        self._address = address
        self._encrypted = encrypted

        self._client: BleakClient | None = None
        self._lock = asyncio.Lock()
        self._notify_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._notify_buffer = bytearray()

        self._protocol_version: int | None = None
        self._random_md5 = ""
        self._aes_key = ""
        self._share_key = ""
        self._iot_public_key: ec.EllipticCurvePublicKey | None = None
        self._local_private_key: ec.EllipticCurvePrivateKey | None = None

    async def async_read_home_data(self) -> BluettiHomeData:
        async with self._lock:
            try:
                await self._async_ensure_connected()

                if self._protocol_version is None:
                    self._protocol_version = await self._async_read_protocol_version()

                reg_len = _get_home_data_reg_len(self._protocol_version)
                payload = await self._async_read_register(REG_APP_HOME_DATA, reg_len)
                return _parse_home_data(payload, self._protocol_version)
            except (BleakError, TimeoutError, ValueError, InvalidSignature) as err:
                await self._async_disconnect_locked()
                raise BluettiBleError(str(err)) from err

    async def async_disconnect(self) -> None:
        async with self._lock:
            await self._async_disconnect_locked()

    async def _async_disconnect_locked(self) -> None:
        if self._client is not None:
            try:
                if self._client.is_connected:
                    await self._client.disconnect()
            except BleakError:
                _LOGGER.debug("Disconnect failed for %s", self._address, exc_info=True)

        self._client = None
        self._clear_notifications()
        self._reset_encryption_state()

    async def _async_ensure_connected(self) -> None:
        if self._client is not None and self._client.is_connected:
            return

        ble_device = bluetooth.async_ble_device_from_address(
            self._hass,
            self._address,
            connectable=True,
        )
        if ble_device is None:
            raise BluettiBleError(f"BLE device {self._address} is not available")

        self._client = BleakClient(ble_device, timeout=BLE_CONNECT_TIMEOUT)
        await self._client.connect()
        await self._client.start_notify(NOTIFY_CHAR_UUID, self._handle_notification)
        self._clear_notifications()

        if self._encrypted:
            await self._async_perform_handshake()

    def _handle_notification(self, _characteristic: object, data: bytearray) -> None:
        self._notify_queue.put_nowait(bytes(data))

    async def _async_perform_handshake(self) -> None:
        if self._share_key:
            return

        self._clear_notifications()

        challenge = await self._async_read_plain_handshake_frame(expected_type=0x01)
        random_bytes = challenge[4:8]
        self._random_md5 = md5(random_bytes[::-1]).hexdigest().upper()
        self._aes_key = _xor_hex(self._random_md5, LOCAL_AES_KEY)

        suffix = self._random_md5[16:24]
        response_body = f"0204{suffix}"
        await self._async_write_packet(bytes.fromhex(f"2A2A{response_body}{_hex_str_sum(response_body)}"))

        phase2_packet = await self._async_read_encrypted_frame(iv=bytes.fromhex(self._random_md5))
        phase2_plain = bytes.fromhex(
            _parse_aes_cbc_data(
                phase2_packet.hex().upper(),
                self._aes_key,
                iv=bytes.fromhex(self._random_md5),
            )
        )
        if len(phase2_plain) < 70 or phase2_plain[:2] != _HANDSHAKE_PREFIX or phase2_plain[2] != 0x04:
            raise BluettiBleError("Unexpected encrypted handshake step 2 packet")

        iot_public_key_raw = phase2_plain[4:68]
        signature_raw = phase2_plain[68:-2]
        _verify_signature(iot_public_key_raw + bytes.fromhex(self._random_md5), signature_raw)

        self._iot_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b"\x04" + iot_public_key_raw,
        )
        self._local_private_key = ec.generate_private_key(ec.SECP256R1())

        local_public_key_raw = self._local_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )[1:]
        signature = _sign_raw(local_public_key_raw + bytes.fromhex(self._random_md5))
        phase3_body = f"0580{local_public_key_raw.hex().upper()}{signature.hex().upper()}"
        await self._async_write_packet(bytes.fromhex(f"2A2A{phase3_body}{_hex_str_sum(phase3_body)}"))

        phase3_packet = await self._async_read_encrypted_frame(iv=bytes.fromhex(self._random_md5))
        phase3_plain = bytes.fromhex(
            _parse_aes_cbc_data(
                phase3_packet.hex().upper(),
                self._aes_key,
                iv=bytes.fromhex(self._random_md5),
            )
        )
        if len(phase3_plain) < 5 or phase3_plain[:2] != _HANDSHAKE_PREFIX or phase3_plain[2] != 0x06:
            raise BluettiBleError("Unexpected encrypted handshake step 3 packet")
        if phase3_plain[4] != 0x00:
            raise BluettiBleError("Device rejected encrypted handshake")
        if self._iot_public_key is None or self._local_private_key is None:
            raise BluettiBleError("Encrypted handshake did not produce a valid key pair")

        self._share_key = self._local_private_key.exchange(ec.ECDH(), self._iot_public_key).hex().upper()
        self._aes_key = ""
        self._iot_public_key = None

    async def _async_read_protocol_version(self) -> int:
        payload = await self._async_read_register(REG_BASE_CONFIG, REG_BASE_CONFIG_LEN)
        if len(payload) < 32:
            raise BluettiBleError("Base config response is too short")

        protocol_version = int.from_bytes(payload[30:32], byteorder="big", signed=False)
        if protocol_version == 0:
            raise BluettiBleError("Protocol version is missing from base config")
        return protocol_version

    async def _async_read_register(self, reg_addr: int, reg_len: int) -> bytes:
        command = _build_read_command(reg_addr, reg_len, MODBUS_SLAVE_ADDRESS)
        response = await self._async_send_command(command, expected_payload_len=reg_len * 2)
        if len(response) < 5:
            raise BluettiBleError("Modbus response is too short")
        if response[1] != MODBUS_READ_FUNCTION:
            raise BluettiBleError(f"Unexpected Modbus function 0x{response[1]:02X}")
        if response[2] != reg_len * 2:
            raise BluettiBleError(
                f"Unexpected Modbus payload length {response[2]}, expected {reg_len * 2}"
            )
        if _crc16_modbus(response[:-2]) != int.from_bytes(response[-2:], byteorder="little"):
            raise BluettiBleError("CRC mismatch in Modbus response")
        return response[3:-2]

    async def _async_send_command(self, command_hex: str, expected_payload_len: int) -> bytes:
        self._clear_notifications()

        if self._encrypted:
            if not self._share_key:
                raise BluettiBleError("Encrypted connection is not initialized")
            packet_hex = _build_aes_cbc_cmd(command_hex, self._share_key)
            await self._async_write_packet(bytes.fromhex(packet_hex))
            encrypted_response = await self._async_read_encrypted_frame(iv=None)
            response_hex = _parse_aes_cbc_data(encrypted_response.hex().upper(), self._share_key)
            response = bytes.fromhex(response_hex)
        else:
            await self._async_write_packet(bytes.fromhex(command_hex))
            response = await self._async_read_plain_modbus_response(expected_payload_len + 5)

        return response

    async def _async_write_packet(self, packet: bytes) -> None:
        if self._client is None:
            raise BluettiBleError("BLE client is not connected")

        for index in range(0, len(packet), WRITE_CHUNK_SIZE):
            chunk = packet[index : index + WRITE_CHUNK_SIZE]
            await self._client.write_gatt_char(WRITE_CHAR_UUID, chunk, response=False)
            if index + WRITE_CHUNK_SIZE < len(packet):
                await asyncio.sleep(WRITE_CHUNK_DELAY)

    async def _async_read_plain_modbus_response(self, expected_len: int) -> bytes:
        return await self._async_read_exact_length(expected_len)

    async def _async_read_plain_handshake_frame(self, expected_type: int) -> bytes:
        deadline = asyncio.get_running_loop().time() + BLE_COMMAND_TIMEOUT

        while True:
            frame = await self._async_read_handshake_frame(deadline)
            if frame[2] == 0x03:
                continue
            if frame[2] != expected_type:
                raise BluettiBleError(f"Unexpected handshake frame type 0x{frame[2]:02X}")
            return frame

    async def _async_read_encrypted_frame(self, iv: bytes | None) -> bytes:
        deadline = asyncio.get_running_loop().time() + BLE_COMMAND_TIMEOUT

        while True:
            ignored_frame = self._pop_handshake_ack_frame()
            if ignored_frame is not None:
                continue

            expected_len = _encrypted_packet_length(self._notify_buffer, iv)
            if expected_len is not None and len(self._notify_buffer) >= expected_len:
                packet = bytes(self._notify_buffer[:expected_len])
                del self._notify_buffer[:expected_len]
                return packet

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for encrypted BLE response")

            self._notify_buffer.extend(await asyncio.wait_for(self._notify_queue.get(), remaining))

    async def _async_read_handshake_frame(self, deadline: float) -> bytes:
        while True:
            expected_len = _plain_handshake_packet_length(self._notify_buffer)
            if expected_len is not None and len(self._notify_buffer) >= expected_len:
                packet = bytes(self._notify_buffer[:expected_len])
                del self._notify_buffer[:expected_len]
                return packet

            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for BLE handshake frame")

            self._notify_buffer.extend(await asyncio.wait_for(self._notify_queue.get(), remaining))

    async def _async_read_exact_length(self, expected_len: int) -> bytes:
        deadline = asyncio.get_running_loop().time() + BLE_COMMAND_TIMEOUT

        while len(self._notify_buffer) < expected_len:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for BLE response")

            self._notify_buffer.extend(await asyncio.wait_for(self._notify_queue.get(), remaining))

        packet = bytes(self._notify_buffer[:expected_len])
        del self._notify_buffer[:expected_len]
        return packet

    def _pop_handshake_ack_frame(self) -> bytes | None:
        expected_len = _plain_handshake_packet_length(self._notify_buffer)
        if expected_len is None or len(self._notify_buffer) < expected_len:
            return None
        if self._notify_buffer[2] != 0x03:
            return None

        packet = bytes(self._notify_buffer[:expected_len])
        del self._notify_buffer[:expected_len]
        return packet

    def _clear_notifications(self) -> None:
        self._notify_buffer.clear()
        while not self._notify_queue.empty():
            self._notify_queue.get_nowait()

    def _reset_encryption_state(self) -> None:
        self._random_md5 = ""
        self._aes_key = ""
        self._share_key = ""
        self._iot_public_key = None
        self._local_private_key = None


def _get_home_data_reg_len(protocol_version: int) -> int:
    if protocol_version >= 2017:
        return 93
    if protocol_version >= 2015:
        return 92
    if protocol_version >= 2014:
        return 89
    if protocol_version >= 2013:
        return 78
    if protocol_version >= 2010:
        return 72
    if protocol_version >= 2008:
        return 71
    if protocol_version > 2000:
        return 62
    return 56


def _parse_home_data(payload: bytes, protocol_version: int) -> BluettiHomeData:
    if len(payload) < 100:
        raise BluettiBleError("Home data payload is too short for AC200L")

    return BluettiHomeData(
        protocol_version=protocol_version,
        model=_parse_swapped_ascii(payload[20:32]),
        battery_voltage=int.from_bytes(payload[0:2], byteorder="big", signed=False) / 10,
        battery_current=int.from_bytes(payload[2:4], byteorder="big", signed=False) / 10,
        battery_soc=int.from_bytes(payload[4:6], byteorder="big", signed=False),
        dc_output_power=_swap_u32(payload[80:84]),
        ac_output_power=_swap_s32(payload[84:88]),
        pv_input_power=_swap_u32(payload[88:92]),
        grid_power=_swap_s32(payload[92:96]),
        inverter_power=_swap_s32(payload[96:100]),
    )


def _parse_swapped_ascii(data: bytes) -> str:
    chars: list[str] = []
    for index in range(0, len(data), 2):
        second = data[index + 1]
        first = data[index]
        if second:
            chars.append(chr(second))
        if first:
            chars.append(chr(first))
    return "".join(chars)


def _swap_u32(data: bytes) -> int:
    return int.from_bytes(data[2:4] + data[0:2], byteorder="big", signed=False)


def _swap_s32(data: bytes) -> int:
    return int.from_bytes(data[2:4] + data[0:2], byteorder="big", signed=True)


def _build_read_command(reg_addr: int, reg_len: int, slave_addr: int) -> str:
    payload = bytes(
        [slave_addr, MODBUS_READ_FUNCTION]
        + list(reg_addr.to_bytes(2, byteorder="big"))
        + list(reg_len.to_bytes(2, byteorder="big"))
    )
    crc = _crc16_modbus(payload)
    return (payload + crc.to_bytes(2, byteorder="little")).hex().upper()


def _crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def _build_aes_cbc_cmd(cmd_hex: str, aes_key_hex: str, iv: bytes | None = None) -> str:
    plaintext = bytes.fromhex(cmd_hex)
    length_prefix = f"{len(plaintext):04X}"

    if iv is None:
        iv_seed = os.urandom(4)
        iv = bytes.fromhex(md5(iv_seed).hexdigest().upper())
        iv_seed_hex = iv_seed.hex().upper()
    else:
        iv_seed_hex = ""

    padded = plaintext + bytes((16 - len(plaintext) % 16) % 16)
    cipher = Cipher(algorithms.AES(bytes.fromhex(aes_key_hex)), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return f"{length_prefix}{iv_seed_hex}{ciphertext.hex().upper()}"


def _parse_aes_cbc_data(data_hex: str, aes_key_hex: str, iv: bytes | None = None) -> str:
    data_hex = data_hex.replace(" ", "")
    plain_len = int(data_hex[:4], 16)

    if iv is None:
        iv_seed = bytes.fromhex(data_hex[4:12])
        iv = bytes.fromhex(md5(iv_seed).hexdigest().upper())
        ciphertext_hex = data_hex[12:]
    else:
        ciphertext_hex = data_hex[4:]

    cipher = Cipher(algorithms.AES(bytes.fromhex(aes_key_hex)), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(bytes.fromhex(ciphertext_hex)) + decryptor.finalize()
    return plaintext[:plain_len].hex().upper()


def _encrypted_packet_length(data: bytearray, iv: bytes | None) -> int | None:
    if len(data) < 2:
        return None

    plain_len = int.from_bytes(data[:2], byteorder="big", signed=False)
    encrypted_len = ((plain_len + 15) // 16) * 16
    if iv is None:
        return 6 + encrypted_len if len(data) >= 6 else None
    return 2 + encrypted_len


def _plain_handshake_packet_length(data: bytearray) -> int | None:
    if len(data) < 4 or data[:2] != _HANDSHAKE_PREFIX:
        return None
    return data[3] + 6


def _hex_str_sum(hex_str: str, return_byte_len: int = 2) -> str:
    total = 0
    for index in range(0, len(hex_str), 2):
        total += int(hex_str[index : index + 2], 16)
    return f"{total:0{return_byte_len * 2}X}"


def _xor_hex(first: str, second: str) -> str:
    if len(first) != len(second):
        raise BluettiBleError("HEX strings must have the same length")

    parts: list[str] = []
    for index in range(0, len(first), 2):
        left = int(first[index : index + 2], 16)
        right = int(second[index : index + 2], 16)
        parts.append(f"{left ^ right:02X}")
    return "".join(parts)


def _verify_signature(data: bytes, signature_raw: bytes) -> None:
    if len(signature_raw) % 2 != 0:
        raise BluettiBleError("Invalid handshake signature length")

    half = len(signature_raw) // 2
    der_signature = encode_dss_signature(
        int.from_bytes(signature_raw[:half], byteorder="big", signed=False),
        int.from_bytes(signature_raw[half:], byteorder="big", signed=False),
    )
    _STATIC_PUBLIC_KEY.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))


def _sign_raw(data: bytes) -> bytes:
    der_signature = _STATIC_PRIVATE_KEY.sign(data, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    return r_value.to_bytes(32, byteorder="big") + s_value.to_bytes(32, byteorder="big")