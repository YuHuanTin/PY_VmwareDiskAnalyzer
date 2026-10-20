from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SECTOR = 512
VMX_SUFFIX = ".vmx"
DISK_SUFFIXES = (".vmdk", ".vmdk.raw")
KIND_ORDER = {"D": 0, "M": 1, "S": 2, "C": 3, "I": 4, "X": 5, "N": 6, "B": 7}
KIND_LEGEND = (
    "D(isk) 磁盘 · M(em) 内存 · S(tate) 快照状态 · C(heckpoint) 检查点 · "
    "I(ndex) 快照索引 · X(mx) 配置 · N(vram) 固件变量 · B(oard) 统计"
)
KEY_WIDTH = 8  # 基本信息栏的键列宽 (按显示宽度)

# 磁盘节点形如 scsi0:0 / nvme0:0 / ide1:0
DISK_NODE_RE = re.compile(r"^(?P<node>[A-Za-z_]+\d+:\d+)\.fileName$")
# 描述符中的 extent 行: RW 8323072 SPARSE "disk-s001.vmdk"
EXTENT_RE = re.compile(
    r'^(?P<access>RW|RDONLY|NOACCESS)\s+(?P<sectors>\d+)\s+(?P<type>[A-Za-z0-9_]+)\s+"(?P<file>[^"]+)"(?P<rest>.*)$'
)
FLAT_OFFSET_RE = re.compile(r"offset\s*=\s*(\d+)|^\s*(\d+)")
# .vmsn 二进制里嵌的文件名
VMEM_REF_RE = re.compile(rb"[^\x00-\x1f\"'<>\|\*\?]{3,160}\.(vmdk|vmem)")

SPARSE_MAGIC = 0x564D444B  # 'KDMV'
FLAT_MAGIC = 0x20544C46  # 'FLAT'
STREAM_MAGIC = 0x45524153  # 'SARE'


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def humanSize(num: float) -> str:
    """把字节数格式化成 GiB/MiB 形式."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < 1024 or unit == "PiB":
            if unit == "B":
                return f"{int(num)} B"
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} PiB"


def splitSize(text: str) -> tuple[str, str]:
    """把 "11.80 GiB" 拆成 ("11.80", "GiB")."""
    if " " in text:
        num, unit = text.rsplit(" ", 1)
        return num, unit
    return text, ""


def combinedSize(disk: int, mem: int) -> str:
    """磁盘 + 内存 合并显示, 单位相同时只写一次: 11.80+12.12GiB."""
    if not disk:
        return humanSize(mem).replace(" ", "")
    if not mem:
        return humanSize(disk).replace(" ", "")
    dNum, dUnit = splitSize(humanSize(disk))
    mNum, mUnit = splitSize(humanSize(mem))
    if dUnit == mUnit:
        return f"{dNum} + {mNum}{dUnit}"
    return f"{dNum}{dUnit} + {mNum}{mUnit}"


def decodeText(raw: bytes) -> str:
    """按 utf-8 / gbk 的顺序解码, 尽量不丢内容."""
    for enc in ("utf-8-sig", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def normalizeUUID(raw: str) -> str:
    """把 .vmx 里的 uuid.bios 归一化成 8-4-4-4-12 形式."""
    hexs = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(hexs) != 32:
        return ""
    return f"{hexs[0:8]}-{hexs[8:12]}-{hexs[12:16]}-{hexs[16:20]}-{hexs[20:32]}"


def dispWidth(text: str) -> int:
    """终端显示宽度: 中文/全角字符占 2 列."""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def padTo(text: str, width: int, align: str = "<") -> str:
    """按显示宽度补齐, 而不是按字符数."""
    gap = max(0, width - dispWidth(text))
    if align == ">":
        return " " * gap + text
    if align == "^":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def tableLines(headers: list[str], rows: list[list[str]], aligns: list[str] | None = None) -> list[str]:
    """渲染一个列对齐的表格."""
    cols = len(headers)
    aligns = aligns or ["<"] * cols
    widths = [dispWidth(h) for h in headers]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], dispWidth(row[i]))
    lines = ["  ".join(padTo(h, widths[i], aligns[i]) for i, h in enumerate(headers)).rstrip()]
    for row in rows:
        lines.append("  ".join(padTo(row[i], widths[i], aligns[i]) for i in range(cols)).rstrip())
    return lines


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetCompressedFileSizeW.restype = wintypes.DWORD

    def fileSizeOnDisk(path: Path) -> int:
        """文件在磁盘上实际占用的字节数 (稀疏文件下小于 st_size)."""
        ctypes.set_last_error(0)
        high = wintypes.DWORD()
        low = _kernel32.GetCompressedFileSizeW(str(path), ctypes.byref(high))
        if low != 0xFFFFFFFF or ctypes.get_last_error() == 0:
            return (high.value << 32) | low
        return path.stat().st_size

else:  # pragma: no cover - 非 Windows 平台退化为 st_size

    def fileSizeOnDisk(path: Path) -> int:
        return path.stat().st_size


# --------------------------------------------------------------------------
# 目录索引: 扫一次, 之后全部走内存
# --------------------------------------------------------------------------
@dataclass
class FileEntry:
    name: str
    path: Path
    size: int  # 实际占盘字节数
    logical: int  # 文件逻辑长度 (st_size)
    mtime: float

    @property
    def mtimeDT(self) -> datetime | None:
        try:
            return datetime.fromtimestamp(self.mtime)
        except (OSError, OverflowError, ValueError):
            return None


class DirIndex:
    """一次扫描目录得到全部文件路径/大小/时间, 之后按路径直接取用."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.files: dict[str, FileEntry] = {}
        self.subdirs: list[str] = []
        self._images: dict[str, DiskImage | None] = {}
        self._snapshotRefs: tuple[set[str], set[str]] | None = None
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            stat = entry.stat(follow_symlinks=False)
                            path = Path(entry.path)
                            self.files[entry.name] = FileEntry(
                                entry.name, path, fileSizeOnDisk(path), stat.st_size, stat.st_mtime
                            )
                        elif entry.is_dir(follow_symlinks=False):
                            self.subdirs.append(entry.name)
                    except OSError:
                        continue
        except OSError:
            pass

    def entry(self, name: str) -> FileEntry | None:
        return self.files.get(name)

    def exists(self, name: str) -> bool:
        return name in self.files

    def size(self, name: str) -> int:
        entry = self.files.get(name)
        return entry.size if entry else 0

    def mtime(self, name: str) -> datetime | None:
        entry = self.files.get(name)
        return entry.mtimeDT if entry else None

    def names(self, suffix: str) -> list[str]:
        return sorted(n for n in self.files if n.lower().endswith(suffix))

    def vmxFiles(self) -> list[str]:
        return self.names(VMX_SUFFIX)

    def totalSize(self) -> int:
        return sum(e.size for e in self.files.values())

    def image(self, name: str) -> DiskImage | None:
        """按需读取一个 vmdk 的描述信息, 结果缓存."""
        if name not in self._images:
            entry = self.files.get(name)
            self._images[name] = readDiskImage(entry.path, entry.logical) if entry else None
        return self._images[name]

    def snapshotRefs(self) -> tuple[set[str], set[str]]:
        """按需扫描 .vmsn 里引用的磁盘/内存快照名, 结果缓存."""
        if self._snapshotRefs is None:
            self._snapshotRefs = findSnapshotRefs(self)
        return self._snapshotRefs


# --------------------------------------------------------------------------
# 配置文件解析 (.vmx / .vmsd / .vmxf)
# --------------------------------------------------------------------------
def parseConfigFile(path: Path) -> dict[str, str]:
    """解析 VMware 的 key = "value" 文本配置."""
    data: dict[str, str] = {}
    try:
        raw = path.read_bytes()
    except OSError:
        return data
    for line in decodeText(raw).splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        data[key] = value
    return data


# --------------------------------------------------------------------------
# VMDK 描述符 / 单体盘
# --------------------------------------------------------------------------
@dataclass
class Extent:
    access: str
    sectors: int
    kind: str
    file: str
    offset: int = 0

    @property
    def byteLength(self) -> int:
        return self.sectors * SECTOR


@dataclass
class Descriptor:
    createType: str = ""
    cid: str = ""
    parentCID: str = ""
    parentHint: str | None = None
    extents: list[Extent] = field(default_factory=list)


def parseDescriptorText(text: str) -> Descriptor:
    """解析 VMDK 描述符文本."""
    desc = Descriptor()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        m = EXTENT_RE.match(line)
        if m:
            rest = m.group("rest").strip()
            offset = 0
            om = FLAT_OFFSET_RE.search(rest)
            if om:
                offset = int(om.group(1) or om.group(2))
            desc.extents.append(
                Extent(m.group("access"), int(m.group("sectors")), m.group("type").upper(), m.group("file"), offset)
            )
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        if key == "createType":
            desc.createType = value
        elif key == "CID":
            desc.cid = value
        elif key == "parentCID":
            desc.parentCID = value
        elif key == "parentFileNameHint":
            desc.parentHint = value
    return desc


@dataclass
class DiskImage:
    """一个 vmdk 文件 (描述符文件或单体盘)."""

    path: Path
    kind: str = "unknown"
    createType: str = ""
    cid: str = ""
    parentCID: str = ""
    parentHint: str | None = None
    extents: list[Extent] = field(default_factory=list)
    capacitySectors: int = 0
    monolithic: bool = False

    @property
    def virtualBytes(self) -> int:
        if self.capacitySectors:
            return self.capacitySectors * SECTOR
        return sum(e.byteLength for e in self.extents)

    @property
    def provision(self) -> str:
        ct = self.createType.lower()
        if "sparse" in ct or "stream" in ct:
            return "按需"
        if "flat" in ct:
            return "预分配"
        if "rdm" in ct or "raw" in ct:
            return "裸设备"
        return "未知"


def readDiskImage(path: Path, fileSize: int | None = None) -> DiskImage | None:
    """按需读取一个 vmdk 文件, 返回其描述信息."""
    try:
        with path.open("rb") as f:
            head = f.read(512)
    except OSError:
        return None
    if not head:
        return None

    # 1) 文本描述符
    if head.startswith(b"# Disk DescriptorFile"):
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            return None
        desc = parseDescriptorText(text)
        return DiskImage(
            path=path,
            kind="descriptor",
            createType=desc.createType,
            cid=desc.cid,
            parentCID=desc.parentCID,
            parentHint=desc.parentHint,
            extents=desc.extents,
            capacitySectors=sum(e.sectors for e in desc.extents),
            monolithic=False,
        )

    # 2) 单体稀疏盘 (KDMV)
    #    头部: magic(4) version(4) flags(4) capacity(8) grain(8)
    #          descOffset(8) descSize(8) numGTEsPerGT(4) rgd(8) gd(8) overhead(8)
    if len(head) >= 44 and struct.unpack_from("<I", head, 0)[0] == SPARSE_MAGIC:
        _magic, _version, _flags, capacity, _grainSize, descOffset, descSize = struct.unpack_from("<IIIQQQQ", head, 0)
        desc = Descriptor(createType="monolithicSparse")
        start = descOffset * SECTOR
        length = descSize * SECTOR
        if length and (fileSize is None or length <= fileSize):
            try:
                with path.open("rb") as f:
                    f.seek(start)
                    desc = parseDescriptorText(decodeText(f.read(length)))
            except OSError:
                pass
        if not desc.extents:
            desc.extents = [Extent("RW", capacity, "SPARSE", path.name)]
        return DiskImage(
            path=path,
            kind="monolithic-sparse",
            createType=desc.createType or "monolithicSparse",
            cid=desc.cid,
            parentCID=desc.parentCID,
            parentHint=desc.parentHint,
            extents=desc.extents,
            capacitySectors=capacity,
            monolithic=True,
        )

    # 3) 单体平面盘 (FLAT) / 流式优化盘 (SARE)
    if len(head) >= 12 and struct.unpack_from("<I", head, 0)[0] in (FLAT_MAGIC, STREAM_MAGIC):
        capacity = struct.unpack_from("<Q", head, 8)[0]
        return DiskImage(
            path=path,
            kind="monolithic-flat",
            createType="monolithicFlat",
            extents=[Extent("RW", capacity, "FLAT", path.name)],
            capacitySectors=capacity,
            monolithic=True,
        )

    return DiskImage(path=path, kind="unknown")


# --------------------------------------------------------------------------
# 快照链
# --------------------------------------------------------------------------
@dataclass
class ChainLink:
    image: DiskImage
    bytes: int = 0
    missingParent: str | None = None


def imageBytes(index: DirIndex, image: DiskImage) -> int:
    """该镜像自身 (不含父盘) 占用的磁盘字节数."""
    if image.monolithic:
        return index.size(image.path.name)
    total = 0
    for ext in image.extents:
        if ext.kind == "NOACCESS":
            continue
        if ext.file == image.path.name:
            total += index.size(image.path.name)
            continue
        total += index.size(ext.file)
    return total


def resolveChain(index: DirIndex, leafName: str) -> list[ChainLink]:
    """沿 parentFileNameHint 从当前盘向上还原整条链."""
    chain: list[ChainLink] = []
    seen: set[str] = set()
    current: str | None = leafName
    while current and current not in seen:
        seen.add(current)
        image = index.image(current)
        if image is None:
            break
        link = ChainLink(image)
        chain.append(link)
        hint = image.parentHint
        if not hint:
            break
        if not index.exists(hint):
            link.missingParent = hint
            break
        current = hint
    return chain


# --------------------------------------------------------------------------
# 分析结果
# --------------------------------------------------------------------------
@dataclass
class DiskReport:
    node: str
    fileName: str
    chain: list[ChainLink]
    virtualBytes: int
    diskBytes: int
    missingParent: str | None

    @property
    def provision(self) -> str:
        return self.chain[0].image.provision if self.chain else "未知"


@dataclass
class SnapshotInfo:
    uid: str
    name: str
    parent: str | None
    diskFile: str
    vmsn: str
    mtime: datetime | None
    size: int = 0
    onChain: bool = False
    depth: int = 0


@dataclass
class VMReport:
    vmxPath: Path
    name: str
    guestOS: str
    memMB: int
    vcpu: int
    disks: list[DiskReport] = field(default_factory=list)
    snapshots: list[SnapshotInfo] = field(default_factory=list)
    snapshotNames: dict[str, str] = field(default_factory=dict)
    fileList: list[tuple[str, str, int, str, str]] = field(default_factory=list)
    liveVmem: str = ""
    swapVmemTime: datetime | None = None
    currentDisk: str = ""
    currentDiskBytes: int = 0
    currentDiskTime: datetime | None = None
    currentUid: str | None = None
    branchDeltas: list[tuple[str, int]] = field(default_factory=list)
    orphans: list[tuple[str, int]] = field(default_factory=list)
    snapVmems: list[tuple[str, int, datetime | None]] = field(default_factory=list)
    swapVmems: list[tuple[str, int]] = field(default_factory=list)
    orphanVmems: list[tuple[str, int]] = field(default_factory=list)
    orphanVmsns: list[tuple[str, int]] = field(default_factory=list)
    missingFiles: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    vmDirBytes: int = 0
    vmDirVmdkBytes: int = 0
    vmDirVmemBytes: int = 0

    @property
    def virtualBytes(self) -> int:
        return sum(d.virtualBytes for d in self.disks)

    @property
    def chainBytes(self) -> int:
        return sum(d.diskBytes for d in self.disks)

    @property
    def branchBytes(self) -> int:
        """快照树中不在当前链上的分支增量占用."""
        return sum(size for _, size in self.branchDeltas)

    @property
    def orphanBytes(self) -> int:
        """没有任何引用的残留文件."""
        return (
            sum(size for _, size in self.orphans)
            + sum(size for _, size in self.orphanVmems)
            + sum(size for _, size in self.orphanVmsns)
        )


def parseSnapshots(index: DirIndex, vmsdName: str) -> tuple[list[SnapshotInfo], set[str], str | None]:
    """解析 .vmsd 快照表, 返回 (快照列表, 快照引用的磁盘文件名, 当前快照 uid)."""
    entry = index.entry(vmsdName)
    if entry is None:
        return [], set(), None
    cfg = parseConfigFile(entry.path)
    uids: dict[str, SnapshotInfo] = {}
    diskFiles: set[str] = set()
    for key, value in cfg.items():
        m = re.match(r"^snapshot(\d+)\.(.+)$", key)
        if not m:
            continue
        snapIndex, field = m.group(1), m.group(2)
        if field == "uid":
            uids[snapIndex] = SnapshotInfo(uid=value, name="", parent=None, diskFile="", vmsn="", mtime=None)
            continue
        snap = uids.get(snapIndex)
        if snap is None:
            continue
        if field == "displayName":
            snap.name = value
        elif field == "parent":
            snap.parent = value
        elif field == "filename":
            snap.vmsn = value
        elif field.endswith(".fileName"):
            snap.diskFile = value
            diskFiles.add(value)
    snapshots = [uids[i] for i in sorted(uids, key=lambda x: int(x))]
    for snap in snapshots:
        if snap.vmsn:
            snap.mtime = index.mtime(snap.vmsn)
    return snapshots, diskFiles, cfg.get("snapshot.current")


def findSnapshotRefs(index: DirIndex) -> tuple[set[str], set[str]]:
    """从 .vmsn 快照状态文件里提取引用的磁盘/内存快照文件名.

    .vmsn 里硬编码了每个快照对应的磁盘, 开机时 VMware 会把它们全部打开,
    所以这些文件缺失会直接导致虚拟机无法启动.
    """
    disks: set[str] = set()
    vems: set[str] = set()
    for name in index.names(".vmsn"):
        entry = index.entry(name)
        if entry is None:
            continue
        try:
            raw = entry.path.read_bytes()
        except OSError:
            continue
        for m in VMEM_REF_RE.finditer(raw):
            if m.group(1) == b"vmdk":
                disks.add(m.group(0).decode("utf-8", errors="replace"))
            else:
                vems.add(m.group(0).decode("utf-8", errors="replace"))
    return disks, vems


def vmsnKind(index: DirIndex, name: str) -> str:
    """读 .vmsn 头部的类型串: Snapshot / Checkpoint."""
    entry = index.entry(name)
    if entry is None:
        return "Snapshot"
    try:
        with entry.path.open("rb") as f:
            head = f.read(64)
    except OSError:
        return "Snapshot"
    if len(head) < 16 or head[:4] != b"\xd2\xbe\xd2\xbe":
        return "Snapshot"
    return head[12:].split(b"\x00")[0].decode("utf-8", errors="replace") or "Snapshot"


def analyzeVM(vmxPath: Path, index: DirIndex) -> VMReport:
    """分析单台虚拟机的磁盘占用情况."""
    cfg = parseConfigFile(vmxPath)
    report = VMReport(
        vmxPath=vmxPath,
        name=cfg.get("displayName") or vmxPath.stem,
        guestOS=cfg.get("guestOS", ""),
        memMB=int(cfg.get("memsize", "0") or 0),
        vcpu=int(cfg.get("numvcpus", "0") or 0),
    )

    # --- 磁盘节点 ---
    chainFiles: set[str] = set()
    chainImages: list[DiskImage] = []
    for key, value in sorted(cfg.items()):
        m = DISK_NODE_RE.match(key)
        if not m:
            continue
        value = value.strip()
        if not value or value in ("auto detect", "-1"):
            continue
        if not value.lower().endswith(DISK_SUFFIXES):
            continue
        diskName = Path(value).name
        if not index.exists(diskName):
            report.missingFiles.append(value)
            report.warnings.append(f"虚拟机引用的磁盘文件不存在: {value}")
            continue
        chain = resolveChain(index, diskName)
        for link in chain:
            link.bytes = imageBytes(index, link.image)
        chainFiles.add(diskName)
        for link in chain:
            chainImages.append(link.image)
            chainFiles.add(link.image.path.name)
            for ext in link.image.extents:
                if ext.kind != "NOACCESS" and ext.file != link.image.path.name:
                    chainFiles.add(ext.file)
                    if not index.exists(ext.file):
                        report.missingFiles.append(ext.file)
        virtual = chain[0].image.virtualBytes if chain else 0
        diskBytes = sum(link.bytes for link in chain)
        missing = next((link.missingParent for link in chain if link.missingParent), None)
        report.disks.append(
            DiskReport(
                node=m.group("node"),
                fileName=value,
                chain=chain,
                virtualBytes=virtual,
                diskBytes=diskBytes,
                missingParent=missing,
            )
        )
        if missing is not None:
            report.warnings.append(f"{value} 的父磁盘缺失: {missing}")

    # 当前磁盘 = 磁盘链的首层 (正在写入的那层)
    if report.disks and report.disks[0].chain:
        leaf = report.disks[0].chain[0]
        report.currentDisk = leaf.image.path.name
        report.currentDiskBytes = leaf.bytes
        report.currentDiskTime = index.mtime(report.currentDisk)

    # --- 快照表 ---
    vmsdName = vmxPath.stem + ".vmsd"
    if not index.exists(vmsdName):
        found = index.names(".vmsd")
        vmsdName = found[0] if found else vmsdName
    snapshotDiskFiles: set[str] = set()
    currentUid: str | None = None
    if index.exists(vmsdName):
        report.snapshots, snapshotDiskFiles, currentUid = parseSnapshots(index, vmsdName)
        report.currentUid = currentUid

    # .vmsn 里引用的磁盘同样属于快照树, 开机时也会被打开
    vmsnDiskFiles, vmsnVmemFiles = index.snapshotRefs()

    # --- 快照树: 当前快照及其祖先 = 开机必需, 其余才是可删的分支 ---
    byUid = {s.uid: s for s in report.snapshots}
    ancestorDisks: set[str] = set()
    cursor = currentUid
    walked: set[str] = set()
    while cursor and cursor in byUid and cursor not in walked:
        walked.add(cursor)
        snap = byUid[cursor]
        if snap.diskFile:
            ancestorDisks.add(snap.diskFile)
        cursor = snap.parent

    # --- 快照分支上的磁盘 (不在当前链, 也不在当前快照的祖先链上) ---
    branchFiles: dict[str, int] = {}
    branchExtents: set[str] = set()
    ancestorFiles: set[str] = set()
    for name in sorted(snapshotDiskFiles | vmsnDiskFiles):
        if name in chainFiles:
            continue  # 已经在当前链上
        image = index.image(name)
        if image is None:
            if not index.exists(name):
                report.missingFiles.append(name)
            continue
        extentNames = {ext.file for ext in image.extents if ext.kind != "NOACCESS" and ext.file != name}
        if name in ancestorDisks:
            ancestorFiles.add(name)
            ancestorFiles |= extentNames
            continue
        branchFiles[name] = imageBytes(index, image)
        branchExtents |= extentNames
        for extName in extentNames:
            if not index.exists(extName):
                report.missingFiles.append(extName)

    # --- 每个快照的深度 / 占用 / 是否在当前链上 ---
    for snap in report.snapshots:
        snap.onChain = snap.diskFile in chainFiles
        image = index.image(snap.diskFile) if snap.diskFile else None
        snap.size = imageBytes(index, image) if image else 0
        depth = 0
        cursor = snap.parent
        seen = set()
        while cursor and cursor in byUid and cursor not in seen:
            seen.add(cursor)
            depth += 1
            cursor = byUid[cursor].parent
        snap.depth = depth
        if snap.diskFile:
            report.snapshotNames[snap.diskFile] = snap.name or snap.uid

    # --- 目录内的 vmdk 文件 ---
    missingStems = {n[:-5] for n in report.missingFiles if n.lower().endswith(".vmdk")}
    branch: list[tuple[str, int]] = []
    orphans: list[tuple[str, int]] = []
    for name in index.names(".vmdk"):
        size = index.size(name)
        report.vmDirVmdkBytes += size
        if name in chainFiles or name in ancestorFiles or name in branchExtents:
            continue
        if name in branchFiles:
            branch.append((name, branchFiles[name]))
            continue
        if any(name.startswith(stem + "-") for stem in missingStems):
            continue  # 缺失磁盘留下的分片, 属于损坏的快照
        orphans.append((name, size))
    report.branchDeltas = branch
    report.orphans = orphans

    # --- 内存快照 (.vmem) ---
    # 只有当前保留内存状态的快照才有 .vmem, 旧快照的 .vmem 被删是正常的
    knownVmem = {s.vmsn[:-5] + ".vmem" for s in report.snapshots if s.vmsn.endswith(".vmsn")} | vmsnVmemFiles
    for key in ("uuid.bios", "uuid.location"):
        uuid = normalizeUUID(cfg.get(key, ""))
        if uuid:
            knownVmem.add(f"{uuid}.vmem")
            report.liveVmem = f"{uuid}.vmem"
            break
    for name in index.names(".vmem"):
        size = index.size(name)
        report.vmDirVmemBytes += size
        if name == report.liveVmem:
            report.swapVmems.append((name, size))  # 运行中虚拟机的内存交换文件
            report.swapVmemTime = index.mtime(name)
        elif name in knownVmem:
            report.snapVmems.append((name, size, index.mtime(name)))  # 快照自带的内存状态
        else:
            report.orphanVmems.append((name, size))

    # --- 目录总占用 ---
    report.vmDirBytes = index.totalSize()

    # --- 文件清单: 所有磁盘文件和内存文件, 扁平列出 ---
    owners: dict[str, list[str]] = {}

    def addOwner(name: str, tag: str) -> None:
        if name and name != "-" and tag not in owners.setdefault(name, []):
            owners[name].append(tag)

    for disk in report.disks:
        addOwner(disk.fileName, "当前磁盘")
    for snap in report.snapshots:
        tag = f"快照 [{snap.name or snap.uid}]"
        addOwner(snap.diskFile, tag)
        if snap.vmsn.endswith(".vmsn"):
            addOwner(snap.vmsn[:-5] + ".vmem", tag)
        addOwner(snap.vmsn, tag)
    for name, size in report.swapVmems:
        addOwner(name, "当前运行状态")

    # 分片文件 (extent) 已计入所属磁盘, 不单独列出
    fragments: set[str] = set()
    for image in chainImages:
        for ext in image.extents:
            if ext.kind != "NOACCESS" and ext.file != image.path.name:
                fragments.add(ext.file)
    for name in list(branchFiles) + list(ancestorFiles):
        image = index.image(name)
        if image is None:
            continue
        for ext in image.extents:
            if ext.kind != "NOACCESS" and ext.file != name:
                fragments.add(ext.file)

    for name in sorted(index.names(".vmdk")):
        if name in fragments:
            continue  # 分片文件, 已计入所属磁盘
        image = index.image(name)
        # 磁盘文件的占用 = 描述符本身 + 它的分片
        size = (imageBytes(index, image) if image else 0) or index.size(name)
        fragCount = 0
        if image is not None:
            fragCount = sum(
                1 for ext in image.extents if ext.kind != "NOACCESS" and ext.file != name and index.exists(ext.file)
            )
        report.fileList.append(
            ("D", name, size, " · ".join(owners.get(name, [])) or "无引用", str(fragCount) if fragCount else "-")
        )
    for name, size, _ in report.snapVmems:
        report.fileList.append(("M", name, size, " · ".join(owners.get(name, [])) or "无引用", "-"))
    for name, size in report.swapVmems:
        report.fileList.append(("M", name, size, " · ".join(owners.get(name, [])) or "无引用", "-"))
    for name in sorted(index.names(".vmsn")):
        owner = " · ".join(owners.get(name, [])) or "无引用"
        kind = "C" if vmsnKind(index, name) == "Checkpoint" else "S"
        report.fileList.append((kind, name, index.size(name), owner, "-"))
        if name not in owners:
            report.orphanVmsns.append((name, index.size(name)))
    # 统计文件 (.scoreboard): vmware-vmx 与 UI 共享实时统计的内存文件
    statsName = Path(cfg.get("vmxstats.filename", "")).name
    for name in sorted(index.names(".scoreboard")):
        if name == statsName:
            report.fileList.append(("B", name, index.size(name), "当前运行状态", "-"))
        else:
            report.fileList.append(("B", name, index.size(name), "无引用", "-"))
    # 配置文件与固件状态
    for suffix, kind in ((".vmsd", "I"), (".vmx", "X"), (".vmxf", "X"), (".nvram", "N")):
        for name in sorted(index.names(suffix)):
            report.fileList.append((kind, name, index.size(name), "当前配置", "-"))
    report.fileList.sort(key=lambda f: (KIND_ORDER.get(f[0], 9), f[1]))
    return report


def scanDir(root: Path) -> list[VMReport]:
    """扫描目录, 返回每台虚拟机的分析结果.

    整棵目录树只扫描一次: 每个目录建一份索引, 之后全部按路径取用.
    """
    if root.is_file():
        index = DirIndex(root.parent)
        if root.suffix.lower() != VMX_SUFFIX:
            return []
        return [analyzeVM(root.resolve(), index)]

    indexes: dict[Path, DirIndex] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        index = DirIndex(directory)
        indexes[directory] = index
        for name in index.subdirs:
            if name.startswith((".", "$")) or name.endswith(".lck"):
                continue
            pending.append(directory / name)

    reports: list[VMReport] = []
    for directory in sorted(indexes):
        index = indexes[directory]
        for name in index.vmxFiles():
            reports.append(analyzeVM((directory / name).resolve(), index))
    return reports


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
@dataclass
class Section:
    title: str
    lines: list[str]


@dataclass
class SnapNode:
    """快照树节点: 一个快照同时带磁盘增量和内存状态."""

    label: str
    time: datetime | None
    diskFile: str
    diskSize: int
    memFile: str
    memSize: int
    state: str
    children: list["SnapNode"] = field(default_factory=list)

    @property
    def kind(self) -> str:
        hasDisk = self.diskFile != "-"
        hasMem = self.memFile != "-"
        if hasDisk and hasMem:
            return "D+M"
        if hasMem:
            return "M"
        return "D" if hasDisk else "-"


def buildSnapTree(r: VMReport) -> list[SnapNode]:
    """把 .vmsd 的快照树还原出来, 每个节点带磁盘增量和内存状态."""
    nodes: dict[str, SnapNode] = {}
    for snap in r.snapshots:
        memFile = "-"
        memSize = 0
        if snap.vmsn.endswith(".vmsn"):
            want = snap.vmsn[:-5] + ".vmem"
            for name, size, _ in r.snapVmems:
                if name == want:
                    memFile, memSize = name, size
                    break
        nodes[snap.uid] = SnapNode(
            label=snap.name or snap.uid,
            time=snap.mtime,
            diskFile=snap.diskFile or "-",
            diskSize=snap.size,
            memFile=memFile,
            memSize=memSize,
            state="当前链" if snap.onChain else "分支",
        )

    # 按 .vmsd 的父子关系挂接
    byUid = {s.uid: s for s in r.snapshots}
    for snap in r.snapshots:
        if snap.parent and snap.parent in nodes:
            nodes[snap.parent].children.append(nodes[snap.uid])

    tree = [nodes[s.uid] for s in r.snapshots if not s.parent or s.parent not in byUid]

    # 当前状态: 内存分页文件只在运行中存在, 关机后仅剩当前磁盘
    memFile, memSize, when = "-", 0, r.currentDiskTime
    for name, size in r.swapVmems:
        memFile, memSize = name, size
        when = r.swapVmemTime
    node = SnapNode(
        label="当前",
        time=when,
        diskFile=r.currentDisk or "-",
        diskSize=r.currentDiskBytes,
        memFile=memFile,
        memSize=memSize,
        state="当前",
    )
    current = nodes.get(r.currentUid or "")
    if current is not None:
        current.children.append(node)
    else:
        tree.insert(0, node)
    return tree


def renderTree(items: list[SnapNode]) -> list[tuple[SnapNode, str]]:
    """按树的顺序返回 (节点, 树形前缀)."""
    result: list[tuple[SnapNode, str]] = []

    def walk(nodes: list[SnapNode], prefix: str) -> None:
        for i, node in enumerate(nodes):
            last = i == len(nodes) - 1
            result.append((node, prefix + ("└─ " if last else "├─ ")))
            if node.children:
                walk(node.children, prefix + ("   " if last else "│  "))

    walk(items, "")
    return result


def vmSections(r: VMReport, brief: bool = False) -> list[Section]:
    """组装一台虚拟机的各个展示区块."""
    sections: list[Section] = []

    # 基本信息 (均来自 .vmx, 不随快照变化)
    info = [f"{padTo('配置文件', KEY_WIDTH)} {r.vmxPath.name}"]
    detail = []
    if r.guestOS:
        detail.append(r.guestOS)
    if r.memMB:
        detail.append(f"内存 {humanSize(r.memMB * 1024 * 1024)}")
    if r.vcpu:
        detail.append(f"{r.vcpu} vCPU")
    if detail:
        info.append(f"{padTo('客户机', KEY_WIDTH)} " + " · ".join(detail))
    for d in r.disks:
        info.append(f"{padTo('磁盘', KEY_WIDTH)} {d.node} · {d.provision}")
        info.append(f"{padTo('容量', KEY_WIDTH)} 虚拟 {humanSize(d.virtualBytes)} · 实际 {humanSize(d.diskBytes)}")
    sections.append(Section("基本", info))

    if brief:
        return sections + [Section("文件", usageLines(r))] + problemSection(r)

    # 文件清单 (所有磁盘/内存文件, 扁平列出)
    fileLines: list[str] = []
    if r.fileList:
        rows = [[kind, name, frag, humanSize(size), owner] for kind, name, size, owner, frag in r.fileList]
        fileLines = tableLines(["类型", "文件", "分片", "占用", "归属"], rows, ["<", "<", ">", ">", "<"])
    fileLines.extend(usageLines(r))
    sections.append(Section("文件", fileLines))

    # 快照 (每个快照一行: 磁盘增量 + 内存状态)
    tree = buildSnapTree(r)
    if tree:
        rows = []
        for node, prefix in renderTree(tree):
            when = node.time.strftime("%Y-%m-%d %H:%M") if node.time else "-"
            rows.append(
                [
                    node.kind,
                    prefix + f"[{node.label}]",
                    when,
                    node.diskFile,
                    node.memFile,
                    combinedSize(node.diskSize if node.diskFile != "-" else 0, node.memSize),
                ]
            )
        sections.append(
            Section(
                f"快照 ({len(r.snapshots)})",
                tableLines(
                    ["类型", "快照", "创建时间", "磁盘", "内存", "占用"],
                    rows,
                    ["<", "<", "<", "<", "<", ">"],
                ),
            )
        )

    return sections + problemSection(r)


def usageLines(r: VMReport) -> list[str]:
    other = max(0, r.vmDirBytes - r.vmDirVmdkBytes - r.vmDirVmemBytes)
    parts = [
        f"vmdk {humanSize(r.vmDirVmdkBytes)}",
        f"vmem {humanSize(r.vmDirVmemBytes)}",
        f"其它 {humanSize(other)}",
        f"目录合计 {humanSize(r.vmDirBytes)}",
    ]
    return [" · ".join(parts)]


def problemSection(r: VMReport) -> list[Section]:
    problems = []
    for name in sorted(set(r.missingFiles)):
        problems.append(f"缺失的引用文件  {name}  (会导致开机失败)")
    problems.extend(r.warnings)
    if r.orphans:
        problems.append(f"无引用的磁盘文件 {len(r.orphans)} 个, 合计 {humanSize(sum(s for _, s in r.orphans))}")
        problems.extend(f"    {name}  {humanSize(size)}" for name, size in r.orphans[:15])
        if len(r.orphans) > 15:
            problems.append(f"    … 其余 {len(r.orphans) - 15} 个")
    if r.orphanVmems:
        problems.append(f"无对应的内存快照 {len(r.orphanVmems)} 个, 合计 {humanSize(sum(s for _, s in r.orphanVmems))}")
        problems.extend(f"    {name}  {humanSize(size)}" for name, size in r.orphanVmems[:15])
    if r.orphanVmsns:
        problems.append(
            f"无对应的快照状态文件 {len(r.orphanVmsns)} 个, 合计 {humanSize(sum(s for _, s in r.orphanVmsns))}"
        )
        problems.extend(f"    {name}  {humanSize(size)}" for name, size in r.orphanVmsns[:15])
    return [Section("问题", problems)] if problems else []


def renderVM(r: VMReport, width: int, brief: bool = False) -> list[str]:
    sections = vmSections(r, brief)
    out = [f"┌─ {r.name} " + "─" * max(0, width - 5 - dispWidth(r.name)) + "┐"]
    for i, sec in enumerate(sections):
        if i:
            out.append(f"├─ {sec.title} " + "─" * max(0, width - 5 - dispWidth(sec.title)) + "┤")
        out.extend("│ " + padTo(line, width - 4) + " │" for line in sec.lines)
    out.append("└" + "─" * (width - 2) + "┘")
    return out


def render(root: Path, reports: list[VMReport], brief: bool = False) -> str:
    if not reports:
        return f"目录 {root}\n未找到 .vmx 配置文件."

    blocks = [vmSections(r, brief) for r in reports]
    width = max(76, max(dispWidth(line) for secs in blocks for sec in secs for line in sec.lines) + 4)

    countText = f"{len(reports)} 台虚拟机"
    rootText = f" {root}"
    out = [
        "═" * width,
        padTo(rootText, width),
        padTo(f" {countText}", width),
        f" {padTo('类型', KEY_WIDTH)} {KIND_LEGEND}",
        "═" * width,
    ]
    for r, sections in zip(reports, blocks):
        out.append("")
        out.extend(renderVM(r, width, brief))

    totalVirtual = sum(r.virtualBytes for r in reports)
    totalChain = sum(r.chainBytes for r in reports)
    totalBranch = sum(r.branchBytes for r in reports)
    totalOrphan = sum(r.orphanBytes for r in reports)
    totalDir = sum(r.vmDirBytes for r in reports)
    totalVmdk = sum(r.vmDirVmdkBytes for r in reports)
    totalVmem = sum(r.vmDirVmemBytes for r in reports)

    out.append("")
    out.append("═" * width)
    out.append(f" 合计  {len(reports)} 台虚拟机 · 虚拟容量 {humanSize(totalVirtual)}")
    chainParts = [
        f"当前磁盘链 {humanSize(totalChain)}",
        f"快照分支增量 {humanSize(totalBranch)}",
        f"vmem {humanSize(totalVmem)}",
    ]
    out.append("       " + " · ".join(chainParts))
    dirParts = [
        f"vmdk {humanSize(totalVmdk)}",
        f"vmem {humanSize(totalVmem)}",
        f"其它 {humanSize(totalDir - totalVmdk - totalVmem)}",
    ]
    out.append(f"       目录实际占用 {humanSize(totalDir)}  ({' · '.join(dirParts)})")
    out.append(f"       无引用残留 {humanSize(totalOrphan)}")
    out.append("═" * width)
    return "\n".join(out)


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vmware-disk-analyzer", description="分析 VMware 虚拟机的磁盘占用与快照增量链."
    )
    parser.add_argument("paths", nargs="*", default=["."], help="要扫描的目录或 .vmx 文件")
    parser.add_argument("--brief", action="store_true", help="只输出汇总与问题")
    args = parser.parse_args(argv)

    roots = [Path(p).expanduser() for p in args.paths]
    missing = [p for p in roots if not p.exists()]
    if missing:
        for p in missing:
            print(f"路径不存在: {p}", file=sys.stderr)
        return 2

    groups: list[tuple[Path, list[VMReport]]] = []
    for root in roots:
        groups.append((root, scanDir(root)))

    for i, (root, reports) in enumerate(groups):
        if i:
            print()
        print(render(root, reports, brief=args.brief))
    return 0


if __name__ == "__main__":
    sys.exit(main())
