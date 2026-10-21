
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
from typing import NamedTuple

SECTOR = 512
VMX_SUFFIX = ".vmx"
DISK_SUFFIXES = (".vmdk", ".vmdk.raw")

# 磁盘节点形如 scsi0:0 / nvme0:0 / ide1:0
DISK_NODE_RE = re.compile(r"^(?P<node>[A-Za-z_]+\d+:\d+)\.fileName$")
# 描述符中的 extent 行: RW 8323072 SPARSE "disk-s001.vmdk"
EXTENT_RE = re.compile(
    r'^(?P<access>RW|RDONLY|NOACCESS)\s+(?P<sectors>\d+)\s+(?P<type>[A-Za-z0-9_]+)\s+"(?P<file>[^"]+)"(?P<rest>.*)$'
)
FLAT_OFFSET_RE = re.compile(r"offset\s*=\s*(\d+)|^\s*(\d+)")
# .vmsn 二进制里嵌的文件名
VMEM_REF_RE = re.compile(rb"[^\x00-\x1f\"'<>\|\*\?]{3,160}\.(vmdk|vmem)")
# .vmsn 头部的魔数
VMSN_MAGIC = b"\xd2\xbe\xd2\xbe"

SPARSE_MAGIC = 0x564D444B  # 'KDMV'
FLAT_MAGIC = 0x20544C46  # 'FLAT'
STREAM_MAGIC = 0x45524153  # 'SARE'

# 文件类型代码 (D=磁盘 M=内存 S=快照状态 C=检查点 I=快照索引 X=配置 N=固件变量 B=统计)
KIND_ORDER = {"D": 0, "M": 1, "S": 2, "C": 3, "I": 4, "X": 5, "N": 6, "B": 7}
KIND_LEGEND = (
    "D(isk) 磁盘 · M(em) 内存 · S(tate) 快照状态 · C(heckpoint) 检查点 · "
    "I(ndex) 快照索引 · X(mx) 配置 · N(vram) 固件变量 · B(oard) 统计"
)
KEY_WIDTH = 8  # 基本信息栏的键列宽 (按显示宽度)


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def humanSize(num: float) -> str:
    """把字节数格式化成 GiB/MiB 形式."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < 1024 or unit == "PiB":
            return f"{int(num)} B" if unit == "B" else f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} PiB"


def splitSize(text: str) -> tuple[str, str]:
    """把 "11.80 GiB" 拆成 ("11.80", "GiB")."""
    if " " in text:
        num, unit = text.rsplit(" ", 1)
        return num, unit
    return text, ""


def combinedSize(disk: int, mem: int) -> str:
    """磁盘 + 内存 合并显示, 单位相同时只写一次: 11.80 + 12.12GiB."""
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
        self._snapshotRefs: VmsnRefs | None = None
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

    def totalSize(self) -> int:
        return sum(e.size for e in self.files.values())

    def image(self, name: str) -> DiskImage | None:
        """按需读取一个 vmdk 的描述信息, 结果缓存."""
        if name not in self._images:
            entry = self.files.get(name)
            self._images[name] = readDiskImage(entry.path, entry.logical) if entry else None
        return self._images[name]

    def snapshotRefs(self) -> VmsnRefs:
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
        return sum(e.sectors * SECTOR for e in self.extents)

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

    def extentFiles(self) -> list[str]:
        """该镜像引用的分片文件名 (不含指向自己的情况)."""
        return [e.file for e in self.extents if e.kind != "NOACCESS" and e.file != self.path.name]


def parseDescriptor(path: Path, text: str) -> DiskImage:
    """解析 VMDK 描述符文本."""
    image = DiskImage(path=path, kind="descriptor")
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        m = EXTENT_RE.match(line)
        if m:
            offset = 0
            om = FLAT_OFFSET_RE.search(m.group("rest").strip())
            if om:
                offset = int(om.group(1) or om.group(2))
            image.extents.append(
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
            image.createType = value
        elif key == "CID":
            image.cid = value
        elif key == "parentCID":
            image.parentCID = value
        elif key == "parentFileNameHint":
            image.parentHint = value
    image.capacitySectors = sum(e.sectors for e in image.extents)
    return image


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
        return parseDescriptor(path, text)

    # 2) 单体稀疏盘 (KDMV)
    #    头部: magic(4) version(4) flags(4) capacity(8) grain(8)
    #          descOffset(8) descSize(8) numGTEsPerGT(4) rgd(8) gd(8) overhead(8)
    if len(head) >= 44 and struct.unpack_from("<I", head, 0)[0] == SPARSE_MAGIC:
        _m, _v, _f, capacity, _g, descOffset, descSize = struct.unpack_from("<IIIQQQQ", head, 0)
        image = DiskImage(
            path=path,
            kind="monolithic-sparse",
            createType="monolithicSparse",
            capacitySectors=capacity,
            monolithic=True,
        )
        length = descSize * SECTOR
        if length and (fileSize is None or length <= fileSize):
            try:
                with path.open("rb") as f:
                    f.seek(descOffset * SECTOR)
                    embedded = parseDescriptor(path, decodeText(f.read(length)))
                image.createType = embedded.createType or image.createType
                image.cid, image.parentCID, image.parentHint = embedded.cid, embedded.parentCID, embedded.parentHint
                image.extents = embedded.extents
            except OSError:
                pass
        if not image.extents:
            image.extents = [Extent("RW", capacity, "SPARSE", path.name)]
        return image

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
# 磁盘链
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
    return sum(index.size(name) for name in image.extentFiles())


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
# 快照
# --------------------------------------------------------------------------
@dataclass
class SnapshotInfo:
    uid: str
    name: str
    parent: str | None
    diskFile: str
    vmsn: str
    mtime: datetime | None
    size: int = 0


@dataclass
class SnapshotTable:
    """.vmsd 里的快照树."""

    snapshots: list[SnapshotInfo] = field(default_factory=list)
    diskFiles: set[str] = field(default_factory=set)
    currentUid: str | None = None

    def ancestors(self) -> set[str]:
        """当前快照及其所有祖先的磁盘文件 (开机必需)."""
        byUid = {s.uid: s for s in self.snapshots}
        result: set[str] = set()
        cursor = self.currentUid
        walked: set[str] = set()
        while cursor and cursor in byUid and cursor not in walked:
            walked.add(cursor)
            snap = byUid[cursor]
            if snap.diskFile:
                result.add(snap.diskFile)
            cursor = snap.parent
        return result


class VmsnRefs(NamedTuple):
    """.vmsn 里提到的磁盘/内存文件名."""

    disks: set[str]
    vems: set[str]


class MemoryFiles(NamedTuple):
    """目录里的 .vmem 文件分类."""

    snapshot: list[tuple[str, int, datetime | None]]  # 快照自带的内存状态
    swap: list[tuple[str, int]]  # 运行中虚拟机的内存分页文件
    orphans: list[tuple[str, int]]


def parseSnapshots(index: DirIndex, vmsdName: str) -> SnapshotTable:
    """解析 .vmsd 快照表."""
    entry = index.files.get(vmsdName)
    table = SnapshotTable()
    if entry is None:
        return table
    cfg = parseConfigFile(entry.path)
    uids: dict[str, SnapshotInfo] = {}
    for key, value in cfg.items():
        m = re.match(r"^snapshot(\d+)\.(.+)$", key)
        if not m:
            continue
        snapIndex, fieldName = m.group(1), m.group(2)
        if fieldName == "uid":
            uids[snapIndex] = SnapshotInfo(uid=value, name="", parent=None, diskFile="", vmsn="", mtime=None)
            continue
        snap = uids.get(snapIndex)
        if snap is None:
            continue
        if fieldName == "displayName":
            snap.name = value
        elif fieldName == "parent":
            snap.parent = value
        elif fieldName == "filename":
            snap.vmsn = value
        elif fieldName.endswith(".fileName"):
            snap.diskFile = value
            table.diskFiles.add(value)
    table.snapshots = [uids[i] for i in sorted(uids, key=lambda x: int(x))]
    for snap in table.snapshots:
        if snap.vmsn:
            snap.mtime = index.mtime(snap.vmsn)
    table.currentUid = cfg.get("snapshot.current")
    return table


def findSnapshotRefs(index: DirIndex) -> VmsnRefs:
    """从 .vmsn 快照状态文件里提取引用的磁盘/内存快照文件名.

    .vmsn 里硬编码了每个快照对应的磁盘, 开机时 VMware 会把它们全部打开,
    所以这些文件缺失会直接导致虚拟机无法启动.
    """
    disks: set[str] = set()
    vems: set[str] = set()
    for name in index.names(".vmsn"):
        entry = index.files.get(name)
        if entry is None:
            continue
        try:
            raw = entry.path.read_bytes()
        except OSError:
            continue
        for m in VMEM_REF_RE.finditer(raw):
            text = m.group(0).decode("utf-8", errors="replace")
            (disks if m.group(1) == b"vmdk" else vems).add(text)
    return VmsnRefs(disks, vems)


def vmsnKind(index: DirIndex, name: str) -> str:
    """读 .vmsn 头部的类型串: Snapshot / Checkpoint."""
    entry = index.files.get(name)
    if entry is None:
        return "Snapshot"
    try:
        with entry.path.open("rb") as f:
            head = f.read(64)
    except OSError:
        return "Snapshot"
    if len(head) < 16 or head[:4] != VMSN_MAGIC:
        return "Snapshot"
    return head[12:].split(b"\x00")[0].decode("utf-8", errors="replace") or "Snapshot"


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


class FileRow(NamedTuple):
    """文件清单里的一行."""

    kind: str
    name: str
    size: int
    owner: str
    frag: str = "-"


@dataclass
class VMReport:
    vmxPath: Path
    name: str
    guestOS: str
    memMB: int
    vcpu: int
    disks: list[DiskReport] = field(default_factory=list)
    snapshots: list[SnapshotInfo] = field(default_factory=list)
    fileList: list[FileRow] = field(default_factory=list)
    branchDeltas: list[tuple[str, int]] = field(default_factory=list)
    orphans: list[tuple[str, int]] = field(default_factory=list)
    orphanVmems: list[tuple[str, int]] = field(default_factory=list)
    orphanVmsns: list[tuple[str, int]] = field(default_factory=list)
    memSnapshots: list[tuple[str, int, datetime | None]] = field(default_factory=list)
    memSwap: list[tuple[str, int]] = field(default_factory=list)
    memSwapTime: datetime | None = None
    missingFiles: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    vmDirBytes: int = 0
    vmDirVmdkBytes: int = 0
    vmDirVmemBytes: int = 0
    currentUid: str | None = None
    currentDisk: str = ""
    currentDiskBytes: int = 0
    currentDiskTime: datetime | None = None

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


# --------------------------------------------------------------------------
# 分析
# --------------------------------------------------------------------------
class VMAnalyzer:
    """分析单台虚拟机: 磁盘 -> 快照 -> 内存 -> 文件清单."""

    def __init__(self, vmxPath: Path, index: DirIndex) -> None:
        self.vmxPath = vmxPath
        self.index = index
        self.cfg = parseConfigFile(vmxPath)
        self.report = VMReport(
            vmxPath=vmxPath,
            name=self.cfg.get("displayName") or vmxPath.stem,
            guestOS=self.cfg.get("guestOS", ""),
            memMB=int(self.cfg.get("memsize", "0") or 0),
            vcpu=int(self.cfg.get("numvcpus", "0") or 0),
        )
        self.chainFiles: set[str] = set()
        self.chainImages: list[DiskImage] = []
        self.snapshots = SnapshotTable()
        self.ancestorFiles: set[str] = set()
        self.branchFiles: dict[str, int] = {}
        self.branchExtents: set[str] = set()
        self.memory = MemoryFiles([], [], [])
        self.owners: dict[str, list[str]] = {}

    def run(self) -> VMReport:
        self.analyzeDisks()
        self.analyzeSnapshots()
        self.analyzeMemory()
        self.buildFileList()
        self.report.vmDirBytes = self.index.totalSize()
        return self.report

    def addOwner(self, name: str, tag: str) -> None:
        if name and name != "-" and tag not in self.owners.setdefault(name, []):
            self.owners[name].append(tag)

    def ownerOf(self, name: str) -> str:
        return " · ".join(self.owners.get(name, [])) or "无引用"

    def analyzeDisks(self) -> None:
        """解析 .vmx 里的磁盘节点, 还原磁盘链."""
        index, report = self.index, self.report
        for key, value in sorted(self.cfg.items()):
            m = DISK_NODE_RE.match(key)
            if not m:
                continue
            value = value.strip()
            if not value or value in ("auto detect", "-1") or not value.lower().endswith(DISK_SUFFIXES):
                continue
            diskName = Path(value).name
            if not index.exists(diskName):
                report.missingFiles.append(value)
                report.warnings.append(f"虚拟机引用的磁盘文件不存在: {value}")
                continue
            chain = resolveChain(index, diskName)
            for link in chain:
                link.bytes = imageBytes(index, link.image)
                self.chainImages.append(link.image)
                self.chainFiles.add(link.image.path.name)
                for extName in link.image.extentFiles():
                    self.chainFiles.add(extName)
                    if not index.exists(extName):
                        report.missingFiles.append(extName)
            self.chainFiles.add(diskName)
            missing = next((link.missingParent for link in chain if link.missingParent), None)
            report.disks.append(
                DiskReport(
                    node=m.group("node"),
                    fileName=value,
                    chain=chain,
                    virtualBytes=chain[0].image.virtualBytes if chain else 0,
                    diskBytes=sum(link.bytes for link in chain),
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

    def analyzeSnapshots(self) -> None:
        """解析快照树, 区分当前链上的快照与分支增量."""
        index, report = self.index, self.report
        vmsdName = self.vmxPath.stem + ".vmsd"
        if not index.exists(vmsdName):
            found = index.names(".vmsd")
            vmsdName = found[0] if found else vmsdName
        if index.exists(vmsdName):
            self.snapshots = parseSnapshots(index, vmsdName)
            report.snapshots = self.snapshots.snapshots
            report.currentUid = self.snapshots.currentUid

        # .vmsn 里引用的磁盘同样属于快照树, 开机时也会被打开
        refs = index.snapshotRefs()
        ancestorDisks = self.snapshots.ancestors()

        # 快照分支上的磁盘 (不在当前链, 也不在当前快照的祖先链上)
        for name in sorted(self.snapshots.diskFiles | refs.disks):
            if name in self.chainFiles:
                continue  # 已经在当前链上
            image = index.image(name)
            if image is None:
                if not index.exists(name):
                    report.missingFiles.append(name)
                continue
            extentNames = set(image.extentFiles())
            if name in ancestorDisks:
                self.ancestorFiles.add(name)
                self.ancestorFiles |= extentNames
                continue
            self.branchFiles[name] = imageBytes(index, image)
            self.branchExtents |= extentNames
            for extName in extentNames:
                if not index.exists(extName):
                    report.missingFiles.append(extName)

        # 每个快照的占用
        for snap in report.snapshots:
            image = index.image(snap.diskFile) if snap.diskFile else None
            snap.size = imageBytes(index, image) if image else 0

        # 目录内的 vmdk: 分支增量 / 孤立文件
        missingStems = {n[:-5] for n in report.missingFiles if n.lower().endswith(".vmdk")}
        for name in index.names(".vmdk"):
            size = index.size(name)
            report.vmDirVmdkBytes += size
            if name in self.chainFiles or name in self.ancestorFiles or name in self.branchExtents:
                continue
            if name in self.branchFiles:
                report.branchDeltas.append((name, self.branchFiles[name]))
                continue
            if any(name.startswith(stem + "-") for stem in missingStems):
                continue  # 缺失磁盘留下的分片, 属于损坏的快照
            report.orphans.append((name, size))

    def analyzeMemory(self) -> None:
        """分类目录里的 .vmem: 快照内存状态 / 运行中的分页文件 / 孤立文件."""
        index, report = self.index, self.report
        # 只有当前保留内存状态的快照才有 .vmem, 旧快照的 .vmem 被删是正常的
        known = {s.vmsn[:-5] + ".vmem" for s in report.snapshots if s.vmsn.endswith(".vmsn")}
        known |= index.snapshotRefs().vems
        live = ""
        for key in ("uuid.bios", "uuid.location"):
            uuid = normalizeUUID(self.cfg.get(key, ""))
            if uuid:
                live = f"{uuid}.vmem"
                known.add(live)
                break
        snapshot, swap, orphans = [], [], []
        for name in index.names(".vmem"):
            size = index.size(name)
            report.vmDirVmemBytes += size
            if name == live:
                swap.append((name, size))  # 运行中虚拟机的内存交换文件
                report.memSwapTime = index.mtime(name)
            elif name in known:
                snapshot.append((name, size, index.mtime(name)))  # 快照自带的内存状态
            else:
                orphans.append((name, size))
        self.memory = MemoryFiles(snapshot, swap, orphans)
        report.memSnapshots = snapshot
        report.memSwap = swap
        report.orphanVmems = orphans

    def buildFileList(self) -> None:
        """生成扁平的文件清单 (磁盘/内存/状态/配置/统计)."""
        index, report = self.index, self.report

        # 归属: 哪个文件属于谁
        for disk in report.disks:
            self.addOwner(disk.fileName, "当前磁盘")
        for snap in report.snapshots:
            tag = f"快照 [{snap.name or snap.uid}]"
            self.addOwner(snap.diskFile, tag)
            if snap.vmsn.endswith(".vmsn"):
                self.addOwner(snap.vmsn[:-5] + ".vmem", tag)
            self.addOwner(snap.vmsn, tag)
        for name, _ in self.memory.swap:
            self.addOwner(name, "当前运行状态")

        # 分片文件 (extent) 已计入所属磁盘, 不单独列出
        fragments: set[str] = set()
        for image in self.chainImages:
            fragments |= set(image.extentFiles())
        for name in list(self.branchFiles) + list(self.ancestorFiles):
            image = index.image(name)
            if image is not None:
                fragments |= set(image.extentFiles())

        for name in sorted(index.names(".vmdk")):
            if name in fragments:
                continue
            image = index.image(name)
            # 磁盘文件的占用 = 描述符本身 + 它的分片
            size = (imageBytes(index, image) if image else 0) or index.size(name)
            fragCount = sum(1 for ext in image.extentFiles() if index.exists(ext)) if image else 0
            report.fileList.append(FileRow("D", name, size, self.ownerOf(name), str(fragCount) if fragCount else "-"))
        for name, size, _ in self.memory.snapshot:
            report.fileList.append(FileRow("M", name, size, self.ownerOf(name)))
        for name, size in self.memory.swap:
            report.fileList.append(FileRow("M", name, size, self.ownerOf(name)))
        for name in sorted(index.names(".vmsn")):
            kind = "C" if vmsnKind(index, name) == "Checkpoint" else "S"
            report.fileList.append(FileRow(kind, name, index.size(name), self.ownerOf(name)))
            if name not in self.owners:
                report.orphanVmsns.append((name, index.size(name)))
        # 配置文件与固件状态
        for suffix, kind in ((".vmsd", "I"), (".vmx", "X"), (".vmxf", "X"), (".nvram", "N")):
            for name in sorted(index.names(suffix)):
                report.fileList.append(FileRow(kind, name, index.size(name), "当前配置"))
        # 统计文件 (.scoreboard): vmware-vmx 与 UI 共享实时统计的内存文件
        statsName = Path(self.cfg.get("vmxstats.filename", "")).name
        for name in sorted(index.names(".scoreboard")):
            owner = "当前运行状态" if name == statsName else "无引用"
            report.fileList.append(FileRow("B", name, index.size(name), owner))
        report.fileList.sort(key=lambda row: (KIND_ORDER.get(row.kind, 9), row.name))


def analyzeVM(vmxPath: Path, index: DirIndex) -> VMReport:
    """分析单台虚拟机的磁盘占用情况."""
    return VMAnalyzer(vmxPath, index).run()


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
        for name in index.names(VMX_SUFFIX):
            reports.append(analyzeVM((directory / name).resolve(), index))
    return reports


# --------------------------------------------------------------------------
# 渲染
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
        memFile, memSize = "-", 0
        if snap.vmsn.endswith(".vmsn"):
            want = snap.vmsn[:-5] + ".vmem"
            for name, size, _ in r.memSnapshots:
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
        )

    # 按 .vmsd 的父子关系挂接
    byUid = {s.uid: s for s in r.snapshots}
    for snap in r.snapshots:
        if snap.parent and snap.parent in nodes:
            nodes[snap.parent].children.append(nodes[snap.uid])

    tree = [nodes[s.uid] for s in r.snapshots if not s.parent or s.parent not in byUid]

    # 当前状态: 内存分页文件只在运行中存在, 关机后仅剩当前磁盘
    memFile, memSize, when = "-", 0, r.currentDiskTime
    for name, size in r.memSwap:
        memFile, memSize = name, size
        when = r.memSwapTime
    node = SnapNode(
        label="当前",
        time=when,
        diskFile=r.currentDisk or "-",
        diskSize=r.currentDiskBytes,
        memFile=memFile,
        memSize=memSize,
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


def basicSection(r: VMReport) -> Section:
    """基本信息 (均来自 .vmx, 不随快照变化)."""
    lines = [f"{padTo('配置文件', KEY_WIDTH)} {r.vmxPath.name}"]
    detail = []
    if r.guestOS:
        detail.append(r.guestOS)
    if r.memMB:
        detail.append(f"内存 {humanSize(r.memMB * 1024 * 1024)}")
    if r.vcpu:
        detail.append(f"{r.vcpu} vCPU")
    if detail:
        lines.append(f"{padTo('客户机', KEY_WIDTH)} " + " · ".join(detail))
    for d in r.disks:
        lines.append(f"{padTo('磁盘', KEY_WIDTH)} {d.node} · {d.provision}")
        lines.append(f"{padTo('容量', KEY_WIDTH)} 虚拟 {humanSize(d.virtualBytes)} · 实际 {humanSize(d.diskBytes)}")
    return Section("基本", lines)


def fileSection(r: VMReport) -> Section:
    """文件清单 (所有磁盘/内存文件, 扁平列出)."""
    lines: list[str] = []
    if r.fileList:
        rows = [[row.kind, row.name, row.frag, humanSize(row.size), row.owner] for row in r.fileList]
        lines = tableLines(["类型", "文件", "分片", "占用", "归属"], rows, ["<", "<", ">", ">", "<"])
    lines.extend(usageLines(r))
    return Section("文件", lines)


def snapshotSection(r: VMReport) -> Section:
    """快照树 (每个快照一行: 磁盘增量 + 内存状态)."""
    rows = []
    for node, prefix in renderTree(buildSnapTree(r)):
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
    headers = ["类型", "快照", "创建时间", "磁盘", "内存", "占用"]
    return Section(f"快照 ({len(r.snapshots)})", tableLines(headers, rows, ["<", "<", "<", "<", "<", ">"]))


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
    """问题 (缺失的引用 / 告警 / 残留文件)."""
    problems = []
    for name in sorted(set(r.missingFiles)):
        problems.append(f"缺失的引用文件  {name}  (会导致开机失败)")
    problems.extend(r.warnings)
    for title, items in (
        ("无引用的磁盘文件", r.orphans),
        ("无对应的内存快照", r.orphanVmems),
        ("无对应的快照状态文件", r.orphanVmsns),
    ):
        if items:
            problems.append(f"{title} {len(items)} 个, 合计 {humanSize(sum(s for _, s in items))}")
            problems.extend(f"    {name}  {humanSize(size)}" for name, size in items[:15])
    return [Section("问题", problems)] if problems else []


def vmSections(r: VMReport, brief: bool = False) -> list[Section]:
    """组装一台虚拟机的各个展示区块."""
    sections = [basicSection(r)]
    if brief:
        return sections + [Section("文件", usageLines(r))] + problemSection(r)
    sections.append(fileSection(r))
    sections.append(snapshotSection(r))
    return sections + problemSection(r)


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
    out = [
        "═" * width,
        padTo(f" {root}", width),
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
    totalVmem = sum(r.vmDirVmemBytes for r in reports)
    totalVmdk = sum(r.vmDirVmdkBytes for r in reports)
    totalDir = sum(r.vmDirBytes for r in reports)
    totalOrphan = sum(r.orphanBytes for r in reports)

    out.append("")
    out.append("═" * width)
    out.append(f" 合计  {len(reports)} 台虚拟机 · 虚拟容量 {humanSize(totalVirtual)}")
    out.append(
        f"       当前磁盘链 {humanSize(totalChain)} · 快照分支增量 {humanSize(totalBranch)}"
        f" · vmem {humanSize(totalVmem)}"
    )
    out.append(
        f"       目录实际占用 {humanSize(totalDir)}  "
        f"(vmdk {humanSize(totalVmdk)} · vmem {humanSize(totalVmem)}"
        f" · 其它 {humanSize(totalDir - totalVmdk - totalVmem)})"
    )
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
