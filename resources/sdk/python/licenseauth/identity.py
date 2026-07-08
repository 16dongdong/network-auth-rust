import json
import os
import platform
import socket
from dataclasses import dataclass
from pathlib import Path

from .crypto import generateDeviceKeyPair, generateInstallId, sha256Hex, signDeviceMessage


class IdentityError(Exception):
    pass


@dataclass
class DeviceIdentity:
    installId: str
    privateKeyPem: str
    publicKeyPem: str

    def ready(self) -> bool:
        return bool(self.installId.strip() and self.privateKeyPem.strip() and self.publicKeyPem.strip())

    def sign(self, message: str) -> str:
        if not self.privateKeyPem.strip():
            raise IdentityError("device credential is not initialized")
        return signDeviceMessage(self.privateKeyPem, message)

    def toStorage(self) -> dict[str, str]:
        if not self.ready():
            raise IdentityError("device credential is not initialized")
        return {
            "install_id": self.installId.strip(),
            "device_private_key": self.privateKeyPem.strip(),
            "device_public_key": self.publicKeyPem.strip(),
        }


def generateDeviceIdentity(preferredInstallId: str = "") -> DeviceIdentity:
    keyPair = generateDeviceKeyPair()
    return DeviceIdentity(
        installId=preferredInstallId.strip() or generateInstallId(),
        privateKeyPem=keyPair["device_private_key"],
        publicKeyPem=keyPair["device_public_key"],
    )


def generateDeviceId(appCode: str) -> str:
    payload = canonicalFingerprintPayload(collectFingerprintParts())
    if not payload:
        return generateInstallId()
    return "fp-" + sha256Hex("LicenseAuthDeviceIdV2\n" + appCode.strip() + "\n" + payload)[:48]


def loadOrCreateDeviceIdentity(appCode: str, preferredInstallId: str = "") -> DeviceIdentity:
    installId = preferredInstallId.strip()
    identity = loadDeviceIdentity(appCode)
    if installId and identity.installId != installId:
        identity = generateDeviceIdentity(installId)
        saveDeviceIdentity(appCode, identity)
        return identity
    if not identity.installId:
        identity.installId = installId or generateDeviceId(appCode)
    if not identity.ready():
        identity = generateDeviceIdentity(identity.installId)
        saveDeviceIdentity(appCode, identity)
    return identity


def saveDeviceIdentity(appCode: str, identity: DeviceIdentity) -> None:
    path = identityPath(appCode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(identity.toStorage(), ensure_ascii=False, indent=2), encoding="utf-8")


def loadDeviceIdentity(appCode: str) -> DeviceIdentity:
    path = identityPath(appCode)
    if not path.is_file():
        return DeviceIdentity("", "", "")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise IdentityError("device credential file is invalid") from error
    except OSError as error:
        raise IdentityError("device credential file read failed") from error
    return DeviceIdentity(
        installId=str(data.get("install_id", "")).strip(),
        privateKeyPem=str(data.get("device_private_key", "")).strip(),
        publicKeyPem=str(data.get("device_public_key", "")).strip(),
    )


def identityPath(appCode: str) -> Path:
    safeName = "".join(character if character.isalnum() or character in "-_" else "-" for character in appCode) or "app"
    return identityDirectory() / f"{safeName}.json"


def identityDirectory() -> Path:
    return Path.home() / ".license-auth"


def collectFingerprintParts() -> list[tuple[str, str]]:
    parts: list[tuple[str, str]] = []
    addLinuxSystemFiles(parts)
    addAndroidBuildProperties(parts)
    addCpuInfo(parts)
    addNetworkFingerprints(parts)
    addBlockFingerprints(parts)
    addRuntimeFingerprints(parts)
    return parts


def addLinuxSystemFiles(parts: list[tuple[str, str]]) -> None:
    for name in ("board_serial", "chassis_serial", "product_serial", "product_uuid", "product_name", "sys_vendor"):
        addFileFingerprint(parts, f"dmi.{name}", Path("/sys/class/dmi/id") / name)
    for name in ("serial_number", "soc_id", "machine", "family"):
        addFileFingerprint(parts, f"soc.{name}", Path("/sys/devices/soc0") / name)
    addFileFingerprint(parts, "machine.etc", Path("/etc/machine-id"))
    addFileFingerprint(parts, "machine.dbus", Path("/var/lib/dbus/machine-id"))
    addFileFingerprint(parts, "android.usb.serial", Path("/sys/class/android_usb/android0/iSerial"))


def addAndroidBuildProperties(parts: list[tuple[str, str]]) -> None:
    keys = {
        "ro.boot.hardware",
        "ro.boot.serialno",
        "ro.build.fingerprint",
        "ro.product.board",
        "ro.product.brand",
        "ro.product.device",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.serialno",
    }
    for path in (Path("/system/build.prop"), Path("/vendor/build.prop"), Path("/odm/build.prop")):
        for line in readLimitedFile(path, 65536).splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() in keys:
                addFingerprintPart(parts, "android." + key.strip(), value)


def addCpuInfo(parts: list[tuple[str, str]]) -> None:
    keys = {"Hardware", "Revision", "Serial", "model name"}
    for line in readLimitedFile(Path("/proc/cpuinfo"), 65536).splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in keys:
            addFingerprintPart(parts, "cpu." + key.strip(), value)


def addNetworkFingerprints(parts: list[tuple[str, str]]) -> None:
    netPath = Path("/sys/class/net")
    for interface in directoryChildren(netPath):
        address = readLimitedFile(interface / "address")
        if interface.name != "lo" and address != "00:00:00:00:00:00":
            addFingerprintPart(parts, "net." + interface.name, address)


def addBlockFingerprints(parts: list[tuple[str, str]]) -> None:
    blockPath = Path("/sys/block")
    for device in directoryChildren(blockPath):
        if device.name.startswith(("loop", "ram")):
            continue
        addFileFingerprint(parts, f"block.{device.name}.serial", device / "device" / "serial")
        addFileFingerprint(parts, f"block.{device.name}.wwid", device / "wwid")


def addRuntimeFingerprints(parts: list[tuple[str, str]]) -> None:
    addFingerprintPart(parts, "runtime.system", platform.system())
    addFingerprintPart(parts, "runtime.machine", platform.machine())
    addFingerprintPart(parts, "runtime.node", platform.node() or socket.gethostname())
    addFingerprintPart(parts, "env.computername", os.environ.get("COMPUTERNAME", ""))
    addFingerprintPart(parts, "env.hostname", os.environ.get("HOSTNAME", ""))


def addFileFingerprint(parts: list[tuple[str, str]], name: str, path: Path) -> None:
    addFingerprintPart(parts, name, readLimitedFile(path))


def addFingerprintPart(parts: list[tuple[str, str]], name: str, value: str) -> None:
    normalized = value.strip()
    if usefulFingerprintValue(normalized):
        parts.append((name, normalized))


def usefulFingerprintValue(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(
        normalized
        and normalized not in {"unknown", "none", "default string", "to be filled by o.e.m."}
        and "00000000-0000-0000-0000-000000000000" not in normalized
    )


def readLimitedFile(path: Path, maxBytes: int = 8192) -> str:
    if not path.is_file():
        return ""
    try:
        with path.open("rb") as handle:
            return handle.read(maxBytes).decode("utf-8", errors="ignore").strip()
    except OSError:
        return ""


def directoryChildren(path: Path) -> list[Path]:
    if not path.is_dir():
        return []
    try:
        return sorted(path.iterdir(), key=lambda item: item.name)
    except OSError:
        return []


def canonicalFingerprintPayload(parts: list[tuple[str, str]]) -> str:
    rows = sorted({f"{name}={value}" for name, value in parts})
    return "".join(row + "\n" for row in rows)
