## The v2 package index encoding: column-major row groups.
##
## v1 packs each record's path text, size, flags and package ids into one zstd
## frame, so the compressor never sees a homogeneous stream and every block
## restarts the path prefix delta. v2 keeps the row-group structure that random
## access needs, but gives each column its own frame within the group:
##
## ```text
##   fixed header      record/package/group/trigram counts
##   section table     count x { u16 kind, u16 0, u64 offset, u64 length }
##   package names     newline-separated, zstd
##   package sets      per set: varint count, delta varint package ids, zstd
##   group directory   per group: u64 data offset, u32 first record, u32 count,
##                     then one u32 compressed length per column
##   column data       per group, one zstd frame per column, in column order
##   trigram table     per trigram: 3 bytes trigram, u8 flags, 5 bytes postings
##                     offset; a list ends where the next one begins
##   postings          delta varint group ids, zstd
## ```
##
## Three things this buys over v1, each measured rather than assumed:
##
## - Column-major grouping lets zstd see runs of like values. Sizes stop being
##   interleaved with path bytes.
## - The size column is transposed into byte planes. The high planes of a file
##   size distribution are almost entirely zero, so they collapse; interleaved
##   they were 30% of the whole file, the single largest column after the path
##   suffixes.
## - Only regular files carry a size and only symlinks a target, so no
##   placeholders are stored for the rest.
##
## It also makes a substring scan cheaper than any single mixed stream can be:
## matching only needs the three path columns, so the size, package and target
## columns are decompressed solely for groups that actually contain a hit.

import std/[algorithm, hashes, sets, strutils, tables]
import dbformat
import filemeta
import zstdffi

const
  IndexV2GroupRecords* = 262144
    ## Records per row group, and the one real tuning knob in the format.
    ##
    ## Bigger groups give the compressor more context per column and shrink the
    ## group directory and postings, but a group is the unit a query has to
    ## decode, so they cost read time. Measured over 32Ki to 1Mi on the nixpkgs
    ## corpus: at 40k packages, 64Ki gives 3.191 B/entry and 1Mi gives 2.682,
    ## while a deliberately broad query mix that hits nearly every group slows
    ## by about a third between 64Ki and 256Ki. This sits at the point where the
    ## format is comfortably under nix-index at every scale measured without
    ## paying for the last few percent.
  IndexV2CompressionLevel* = 22
    ## Parity with nix-index, which compresses its single stream at 22.
  IndexV2SizePlanes* = 5
    ## Byte planes per file size, capping a recorded size at 2^40 - 1.
  IndexV2MaxSize* = (1'u64 shl (8 * IndexV2SizePlanes)) - 1

  IndexV2SectionPackageNames = 1'u16
  IndexV2SectionPackageSets = 2'u16
  IndexV2SectionDirectory = 3'u16
  IndexV2SectionColumns = 4'u16
  IndexV2SectionTrigrams = 5'u16
  IndexV2SectionPostings = 6'u16

  IndexV2FixedHeaderSize = 32
  IndexV2SectionEntrySize = 20
  IndexV2TrigramEntrySize = 9
  IndexV2TrigramSkipped = 1'u8

  IndexV2LargeDiff = 0x80'u8
    ## Marks a prefix delta that did not fit in one signed byte.

type
  IndexV2Column* = enum
    ## Column order is part of the format; the directory stores one compressed
    ## length per column in exactly this order.
    colDiff
    colSuffixLen
    colSuffix
    colFlags
    colSize0
    colSize1
    colSize2
    colSize3
    colSize4
    colPkgSet
    colTarget

  IndexV2Group = object
    dataOffset: uint64
    firstRecord: uint32
    recordCount: uint32
    lengths: array[IndexV2Column, uint32]

  IndexV2Trigram = object
    flags: uint8
    postingsOffset: uint64
    postingsLength: uint64

  IndexV2Section = object
    kind: uint16
    offset: uint64
    length: uint64

const
  SizePlaneColumns = [colSize0, colSize1, colSize2, colSize3, colSize4]
  PathColumns* = {colDiff, colSuffixLen, colSuffix}
    ## The columns a substring match needs, and nothing more.

proc kindCode(kind: FileKind): uint8 =
  case kind
  of fkRegular: 0
  of fkDirectory: 1
  of fkSymlink: 2

proc kindOfCode(code: uint8): FileKind =
  case code and 0x3
  of 1: fkDirectory
  of 2: fkSymlink
  else: fkRegular

proc putUint40(value: uint64): string =
  for shift in countup(0, 32, 8):
    result.add(char((value shr shift) and 0xff'u64))

proc getUint40(data: string, offset: int): uint64 =
  if offset < 0 or offset + 5 > data.len:
    dbFail("truncated v2 index")
  for shift in countup(0, 32, 8):
    result = result or (uint64(data[offset + shift div 8]) shl shift)

proc compressColumn(data: string): string =
  if data.len == 0:
    return ""
  try:
    compressBlock(data, IndexV2CompressionLevel)
  except ZstdError as e:
    dbFail("v2 column compression failed: " & e.msg)

proc decompressColumn(data: string): string =
  if data.len == 0:
    return ""
  try:
    decompressFrame(data)
  except ZstdError as e:
    dbFail("v2 column decompression failed: " & e.msg)

proc uniquePathTrigrams(path: string): seq[uint32] =
  var seen = initHashSet[uint32]()
  if path.len < 3:
    return
  for i in 0 .. path.len - 3:
    let trigram =
      (uint32(ord(path[i])) shl 16) or
      (uint32(ord(path[i + 1])) shl 8) or
      uint32(ord(path[i + 2]))
    if trigram notin seen:
      seen.incl(trigram)
      result.add(trigram)

# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

proc internPackages(records: seq[FileEntry],
    names: var seq[string], setOf: var seq[int],
    sets: var seq[seq[int]]) =
  ## Assign every distinct package name an id, then every distinct *set* of
  ## package ids an id. Most paths are shipped by exactly one package and many
  ## share the same set, so storing one set id per record costs far less than a
  ## per-record list.
  # Names are numbered in sorted order rather than first-seen order. Sorted
  # names share long prefixes, so the name table compresses far better, and
  # ids assigned this way put related packages next to each other, which
  # shortens the deltas in the set table.
  var seenNames = initHashSet[string]()
  for record in records:
    for packageName in record.packages:
      if packageName notin seenNames:
        seenNames.incl(packageName)
        names.add(packageName)
  names.sort()

  var nameIds = initTable[string, int]()
  for id, packageName in names:
    nameIds[packageName] = id

  var setIds = initTable[seq[int], int]()
  setOf.setLen(records.len)
  for i, record in records:
    var ids: seq[int]
    for packageName in record.packages:
      ids.add(nameIds[packageName])
    ids.sort()
    var unique: seq[int]
    for id in ids:
      if unique.len == 0 or unique[^1] != id:
        unique.add(id)
    if unique in setIds:
      setOf[i] = setIds[unique]
    else:
      setOf[i] = sets.len
      setIds[unique] = sets.len
      sets.add(unique)

proc encodePackageNames(names: seq[string]): string =
  for i, name in names:
    if i > 0:
      result.add('\n')
    if '\n' in name:
      dbFail("package name contains a newline: " & name)
    result.add(name)

proc encodePackageSets(sets: seq[seq[int]]): string =
  for ids in sets:
    result.add(putVarint(uint64(ids.len)))
    var previous = 0
    for id in ids:
      result.add(putVarint(uint64(id - previous)))
      previous = id

proc appendDiff(column: var string, diff: int) =
  ## frcode-style delta of the shared prefix length: one signed byte when it
  ## fits, otherwise an escape and a big-endian 16-bit value.
  if diff > -127 and diff < 127:
    column.add(char(uint8(diff and 0xff)))
  else:
    if diff < int16.low.int or diff > int16.high.int:
      dbFail("v2 prefix delta out of range")
    column.add(char(IndexV2LargeDiff))
    column.add(char(uint8((diff shr 8) and 0xff)))
    column.add(char(uint8(diff and 0xff)))

proc encodeGroupColumns(records: seq[FileEntry], first, last: int,
    setOf: seq[int], previousPath: var string,
    previousShared: var int): array[IndexV2Column, string] =
  for i in first ..< last:
    let record = records[i]
    let shared = sharedPrefixLen(previousPath, record.path)
    let suffix =
      if shared >= record.path.len: ""
      else: record.path[shared .. ^1]

    result[colDiff].appendDiff(shared - previousShared)
    result[colSuffixLen].add(putVarint(uint64(suffix.len)))
    result[colSuffix].add(suffix)
    result[colFlags].add(char(record.kind.kindCode() or
      (if record.executable: 4'u8 else: 0'u8)))

    # Placeholders for the fields a record cannot carry are pure waste, so a
    # directory contributes nothing to the size or target columns.
    if record.kind == fkRegular:
      if record.size > IndexV2MaxSize:
        dbFail("file size exceeds the v2 size column: " & record.path)
      for plane in 0 ..< IndexV2SizePlanes:
        result[SizePlaneColumns[plane]].add(
          char((record.size shr (8 * plane)) and 0xff'u64))
    if record.kind == fkSymlink:
      result[colTarget].add(putVarint(uint64(record.target.len)))
      result[colTarget].add(record.target)

    result[colPkgSet].add(putVarint(uint64(setOf[i])))

    previousPath = record.path
    previousShared = shared

proc encodeTrigrams(records: seq[FileEntry], groups: seq[(int, int)],
    trigramTable, postings: var string) =
  var postingsByTrigram = initTable[uint32, seq[int]]()
  for groupId, (first, last) in groups:
    var groupTrigrams = initHashSet[uint32]()
    for i in first ..< last:
      for trigram in uniquePathTrigrams(records[i].path):
        groupTrigrams.incl(trigram)
    for trigram in groupTrigrams:
      postingsByTrigram.mgetOrPut(trigram, @[]).add(groupId)

  # A trigram present in most groups cannot narrow anything, so its postings
  # are not worth storing or intersecting.
  let threshold = max(1, groups.len div 8)
  var keys: seq[uint32]
  for trigram in postingsByTrigram.keys:
    keys.add(trigram)
  keys.sort()

  trigramTable.add(putUint32(uint32(keys.len)))
  for trigram in keys:
    let groupIds = postingsByTrigram[trigram]
    let skipped = groupIds.len > threshold
    trigramTable.add(char((trigram shr 16) and 0xff'u32))
    trigramTable.add(char((trigram shr 8) and 0xff'u32))
    trigramTable.add(char(trigram and 0xff'u32))
    trigramTable.add(char(if skipped: IndexV2TrigramSkipped else: 0'u8))
    trigramTable.add(putUint40(uint64(postings.len)))
    if not skipped:
      var previous = 0
      for j, groupId in groupIds:
        postings.add(putVarint(uint64(if j == 0: groupId
                                      else: groupId - previous)))
        previous = groupId

proc sectionEntry(kind: uint16, offset, length: uint64): string =
  result.add(putUint16(kind))
  result.add(putUint16(0'u16))
  result.add(putUint64(offset))
  result.add(putUint64(length))

proc writeIndexV2Payload*(path: string, records: seq[FileEntry],
    groupRecords = IndexV2GroupRecords) =
  ## Write the column-major section payload for `records`, which must already
  ## be sorted by path.
  ##
  ## `groupRecords` is a writer-side choice only: the group directory records
  ## each group's size, so a reader never needs to know what was picked.
  if groupRecords < 1:
    dbFail("v2 row groups must hold at least one record")
  path.ensureParent()

  var
    names: seq[string]
    setOf: seq[int]
    sets: seq[seq[int]]
  internPackages(records, names, setOf, sets)

  var groups: seq[(int, int)]
  var start = 0
  while start < records.len:
    groups.add((start, min(start + groupRecords, records.len)))
    start += groupRecords

  var
    directory: seq[IndexV2Group]
    columnData = ""
    previousPath = ""
    previousShared = 0

  for (first, last) in groups:
    # The prefix delta continues across the group boundary in value but the
    # first record of a group re-encodes its full shared length, so a group
    # stays independently decodable.
    previousPath = ""
    previousShared = 0
    let columns = encodeGroupColumns(records, first, last, setOf,
      previousPath, previousShared)

    var entry = IndexV2Group(
      dataOffset: uint64(columnData.len),
      firstRecord: uint32(first),
      recordCount: uint32(last - first),
    )
    for column in IndexV2Column:
      let compressed = compressColumn(columns[column])
      entry.lengths[column] = uint32(compressed.len)
      columnData.add(compressed)
    directory.add(entry)

  var directoryRaw = ""
  for entry in directory:
    directoryRaw.add(putUint64(entry.dataOffset))
    directoryRaw.add(putUint32(entry.firstRecord))
    directoryRaw.add(putUint32(entry.recordCount))
    for column in IndexV2Column:
      directoryRaw.add(putUint32(entry.lengths[column]))

  var
    trigramRaw = ""
    postingsRaw = ""
  encodeTrigrams(records, groups, trigramRaw, postingsRaw)
  let trigramCount =
    if trigramRaw.len >= 4: getUint32(trigramRaw, 0) else: 0'u32

  let
    namesSection = compressColumn(encodePackageNames(names))
    setsSection = compressColumn(encodePackageSets(sets))
    directorySection = compressColumn(directoryRaw)
    trigramSection = compressColumn(trigramRaw)
    postingsSection = compressColumn(postingsRaw)

  var fixed = ""
  fixed.add(putUint64(uint64(records.len)))
  fixed.add(putUint32(uint32(names.len)))
  fixed.add(putUint32(uint32(sets.len)))
  fixed.add(putUint32(uint32(groups.len)))
  fixed.add(putUint32(trigramCount))
  fixed.add(putUint32(uint32(ord(IndexV2Column.high) + 1)))
  fixed.add(putUint32(6'u32))

  let payloads = [
    (IndexV2SectionPackageNames, namesSection),
    (IndexV2SectionPackageSets, setsSection),
    (IndexV2SectionDirectory, directorySection),
    (IndexV2SectionColumns, columnData),
    (IndexV2SectionTrigrams, trigramSection),
    (IndexV2SectionPostings, postingsSection),
  ]

  var
    sectionTable = ""
    offset = uint64(fixed.len + payloads.len * IndexV2SectionEntrySize)
  for (kind, payload) in payloads:
    sectionTable.add(sectionEntry(kind, offset, uint64(payload.len)))
    offset += uint64(payload.len)

  var output = open(path, fmWrite)
  defer: output.close()
  output.writeRaw(fixed, "v2 fixed header")
  output.writeRaw(sectionTable, "v2 section table")
  for (_, payload) in payloads:
    output.writeRaw(payload, "v2 section")

# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

proc readVarint(data: string, pos: var int): uint64 =
  var shift = 0
  for _ in 0 ..< 10:
    if pos >= data.len:
      dbFail("truncated varint in v2 index")
    let byteValue = ord(data[pos])
    inc pos
    result = result or (uint64(byteValue and 0x7f) shl shift)
    if (byteValue and 0x80) == 0:
      return
    shift += 7
  dbFail("malformed varint in v2 index")

proc readDiff(data: string, pos: var int): int =
  if pos >= data.len:
    dbFail("truncated prefix delta in v2 index")
  let head = uint8(ord(data[pos]))
  inc pos
  if head == IndexV2LargeDiff:
    if pos + 2 > data.len:
      dbFail("truncated wide prefix delta in v2 index")
    let value = (uint16(uint8(ord(data[pos]))) shl 8) or
      uint16(uint8(ord(data[pos + 1])))
    pos += 2
    # The wide form is a two's-complement bit pattern, so it has to be
    # reinterpreted rather than range-converted.
    return int(cast[int16](value))
  int(cast[int8](head))

proc readSection(file: File, path: string, base: int,
    section: IndexV2Section): string =
  if section.offset > uint64(int.high) or section.length > uint64(int.high):
    dbFail("v2 section is too large for this platform")
  if base > int.high - int(section.offset):
    dbFail("v2 section offset overflow")
  file.setFilePos(base + int(section.offset))
  file.readExact(path, int(section.length))

proc findSection(sections: seq[IndexV2Section], kind: uint16): IndexV2Section =
  var found = false
  for section in sections:
    if section.kind == kind:
      if found:
        dbFail("duplicate v2 section")
      result = section
      found = true
  if not found:
    dbFail("missing v2 section")

proc parseDirectory(data: string, groupCount, columnCount: int,
    recordCount: uint64, columnsLength: uint64): seq[IndexV2Group] =
  if columnCount != ord(IndexV2Column.high) + 1:
    dbFail("unexpected v2 column count")
  let entrySize = 16 + columnCount * 4
  if data.len != groupCount * entrySize:
    dbFail("v2 group directory length mismatch")

  var
    expectedRecord = 0'u32
    expectedOffset = 0'u64
  for i in 0 ..< groupCount:
    let base = i * entrySize
    var entry = IndexV2Group(
      dataOffset: getUint64(data, base),
      firstRecord: getUint32(data, base + 8),
      recordCount: getUint32(data, base + 12),
    )
    var total = 0'u64
    for column in IndexV2Column:
      entry.lengths[column] = getUint32(data, base + 16 + ord(column) * 4)
      total += uint64(entry.lengths[column])

    if entry.firstRecord != expectedRecord or entry.dataOffset != expectedOffset:
      dbFail("non-contiguous v2 row groups")
    expectedRecord += entry.recordCount
    expectedOffset += total
    result.add(entry)

  if uint64(expectedRecord) != recordCount or expectedOffset != columnsLength:
    dbFail("v2 group directory does not cover the index")

proc parsePackageNames(data: string, expected: int): seq[string] =
  if expected == 0:
    if data.len != 0:
      dbFail("v2 package name table is not empty")
    return
  var start = 0
  for i in 0 ..< data.len:
    if data[i] == '\n':
      result.add(data[start ..< i])
      start = i + 1
  result.add(data[start .. ^1])
  if result.len != expected:
    dbFail("v2 package name count mismatch")

proc parsePackageSets(data: string, expected, nameCount: int): seq[seq[int]] =
  var pos = 0
  for _ in 0 ..< expected:
    let count = int(readVarint(data, pos))
    var ids: seq[int]
    var previous = 0
    for _ in 0 ..< count:
      let id = previous + int(readVarint(data, pos))
      if id < 0 or id >= nameCount:
        dbFail("invalid v2 package id")
      ids.add(id)
      previous = id
    result.add(ids)
  if pos != data.len:
    dbFail("trailing bytes in v2 package set table")

proc parseTrigrams(data: string, expected: int,
    postingsLength: int): Table[uint32, IndexV2Trigram] =
  if data.len != 4 + expected * IndexV2TrigramEntrySize:
    dbFail("v2 trigram table length mismatch")
  if int(getUint32(data, 0)) != expected:
    dbFail("v2 trigram count mismatch")

  result = initTable[uint32, IndexV2Trigram]()
  var previousTrigram = 0'u32
  for i in 0 ..< expected:
    let base = 4 + i * IndexV2TrigramEntrySize
    let trigram =
      (uint32(ord(data[base])) shl 16) or
      (uint32(ord(data[base + 1])) shl 8) or
      uint32(ord(data[base + 2]))
    if i > 0 and trigram <= previousTrigram:
      dbFail("v2 trigram table is not sorted")
    previousTrigram = trigram

    let offset = getUint40(data, base + 4)
    # A list runs until the next one starts; the final one runs to the end.
    let nextOffset =
      if i == expected - 1: uint64(postingsLength)
      else: getUint40(data, base + IndexV2TrigramEntrySize + 4)
    if nextOffset < offset or nextOffset > uint64(postingsLength):
      dbFail("v2 postings slice out of bounds")

    result[trigram] = IndexV2Trigram(
      flags: uint8(ord(data[base + 3])),
      postingsOffset: offset,
      postingsLength: nextOffset - offset,
    )

proc decodePostings(entry: IndexV2Trigram, postings: string,
    groupCount: int): seq[uint64] =
  var pos = int(entry.postingsOffset)
  let stop = pos + int(entry.postingsLength)
  if stop > postings.len:
    dbFail("v2 postings slice out of bounds")
  var current = 0'u64
  var first = true
  while pos < stop:
    let value = readVarint(postings, pos)
    current = if first: value else: current + value
    first = false
    if current >= uint64(groupCount):
      dbFail("v2 posting group id out of bounds")
    if result.len > 0 and result[^1] >= current:
      dbFail("non-monotonic v2 postings")
    result.add(current)

proc intersectSorted(a, b: seq[uint64]): seq[uint64] =
  var
    i = 0
    j = 0
  while i < a.len and j < b.len:
    if a[i] == b[j]:
      result.add(a[i])
      inc i
      inc j
    elif a[i] < b[j]:
      inc i
    else:
      inc j

proc groupColumn(file: File, path: string, columnsBase: int,
    entry: IndexV2Group, column: IndexV2Column): string =
  ## Read and decompress exactly one column of one group.
  var offset = entry.dataOffset
  for earlier in IndexV2Column:
    if earlier == column:
      break
    offset += uint64(entry.lengths[earlier])
  if offset > uint64(int.high) or columnsBase > int.high - int(offset):
    dbFail("v2 column offset overflow")
  file.setFilePos(columnsBase + int(offset))
  decompressColumn(file.readExact(path, int(entry.lengths[column])))

proc matchingIndexV2*(db: Database, section: DbSection,
    query: string): seq[FileEntry] =
  ## Return every record whose path contains `query`.
  let path = db.path
  var file = open(path, fmRead)
  defer: file.close()

  let base = db.start(section)
  if section.length < uint64(IndexV2FixedHeaderSize):
    dbFail("truncated v2 index header")
  file.setFilePos(base)
  let fixed = file.readExact(path, IndexV2FixedHeaderSize)

  let
    recordCount = getUint64(fixed, 0)
    nameCount = int(getUint32(fixed, 8))
    setCount = int(getUint32(fixed, 12))
    groupCount = int(getUint32(fixed, 16))
    trigramCount = int(getUint32(fixed, 20))
    columnCount = int(getUint32(fixed, 24))
    sectionCount = int(getUint32(fixed, 28))

  if sectionCount != 6:
    dbFail("unexpected v2 section count")
  if groupCount < 0 or trigramCount < 0 or nameCount < 0 or setCount < 0:
    dbFail("implausible v2 header counts")

  let tableRaw = file.readExact(path, sectionCount * IndexV2SectionEntrySize)
  var sections: seq[IndexV2Section]
  for i in 0 ..< sectionCount:
    let entryBase = i * IndexV2SectionEntrySize
    let entry = IndexV2Section(
      kind: getUint16(tableRaw, entryBase),
      offset: getUint64(tableRaw, entryBase + 4),
      length: getUint64(tableRaw, entryBase + 12),
    )
    let endOffset = entry.offset + entry.length
    if endOffset < entry.offset or endOffset > section.length:
      dbFail("v2 section slice out of bounds")
    sections.add(entry)

  let
    namesSection = sections.findSection(IndexV2SectionPackageNames)
    setsSection = sections.findSection(IndexV2SectionPackageSets)
    directorySection = sections.findSection(IndexV2SectionDirectory)
    columnsSection = sections.findSection(IndexV2SectionColumns)
    trigramsSection = sections.findSection(IndexV2SectionTrigrams)
    postingsSection = sections.findSection(IndexV2SectionPostings)

  let
    names = parsePackageNames(
      decompressColumn(file.readSection(path, base, namesSection)), nameCount)
    sets = parsePackageSets(
      decompressColumn(file.readSection(path, base, setsSection)),
      setCount, nameCount)
    directory = parseDirectory(
      decompressColumn(file.readSection(path, base, directorySection)),
      groupCount, columnCount, recordCount, columnsSection.length)
    postings = decompressColumn(
      file.readSection(path, base, postingsSection))
    trigrams = parseTrigrams(
      decompressColumn(file.readSection(path, base, trigramsSection)),
      trigramCount, postings.len)

  var candidates: seq[uint64]
  if query.len < 3:
    for groupId in 0'u64 ..< uint64(groupCount):
      candidates.add(groupId)
  else:
    var lists: seq[seq[uint64]]
    for trigram in uniquePathTrigrams(query):
      if trigram notin trigrams:
        return
      let entry = trigrams[trigram]
      if (entry.flags and IndexV2TrigramSkipped) == 0:
        lists.add(decodePostings(entry, postings, groupCount))
    if lists.len == 0:
      for groupId in 0'u64 ..< uint64(groupCount):
        candidates.add(groupId)
    else:
      lists.sort(proc(a, b: seq[uint64]): int = cmp(a.len, b.len))
      candidates = lists[0]
      for i in 1 ..< lists.len:
        candidates = intersectSorted(candidates, lists[i])
        if candidates.len == 0:
          return

  if columnsSection.offset > uint64(int.high) or
      base > int.high - int(columnsSection.offset):
    dbFail("v2 column section offset overflow")
  let columnsBase = base + int(columnsSection.offset)

  for candidate in candidates:
    if candidate >= uint64(directory.len):
      dbFail("v2 candidate group out of bounds")
    let entry = directory[int(candidate)]

    # Reconstruct this group's paths from the three path columns alone. The
    # remaining columns stay compressed unless something here matches.
    let
      diffs = groupColumn(file, path, columnsBase, entry, colDiff)
      suffixLens = groupColumn(file, path, columnsBase, entry, colSuffixLen)
      suffixes = groupColumn(file, path, columnsBase, entry, colSuffix)

    var
      diffPos = 0
      lenPos = 0
      suffixPos = 0
      previousPath = ""
      shared = 0
      paths = newSeq[string](entry.recordCount)
      hits: seq[int]

    for row in 0 ..< int(entry.recordCount):
      shared += readDiff(diffs, diffPos)
      if shared < 0 or shared > previousPath.len or
          not previousPath.isUtf8Boundary(shared):
        dbFail("invalid v2 path prefix boundary")
      let suffixLen = int(readVarint(suffixLens, lenPos))
      if suffixLen < 0 or suffixPos + suffixLen > suffixes.len:
        dbFail("truncated v2 path suffix")
      let current = previousPath[0 ..< shared] &
        suffixes[suffixPos ..< suffixPos + suffixLen]
      suffixPos += suffixLen
      paths[row] = current
      previousPath = current
      if query in current:
        hits.add(row)

    if hits.len == 0:
      continue

    let
      flags = groupColumn(file, path, columnsBase, entry, colFlags)
      pkgSets = groupColumn(file, path, columnsBase, entry, colPkgSet)
      targets = groupColumn(file, path, columnsBase, entry, colTarget)
    var planes: array[IndexV2SizePlanes, string]
    for plane in 0 ..< IndexV2SizePlanes:
      planes[plane] = groupColumn(file, path, columnsBase, entry,
        SizePlaneColumns[plane])

    if flags.len != int(entry.recordCount):
      dbFail("v2 flag column length mismatch")

    # The variable-width columns only hold entries for the rows that carry
    # them, so walk every row to keep the cursors aligned.
    var
      setPos = 0
      targetPos = 0
      regularIndex = 0
      hitIndex = 0

    for row in 0 ..< int(entry.recordCount):
      let flagByte = uint8(ord(flags[row]))
      let kind = kindOfCode(flagByte)
      let setId = int(readVarint(pkgSets, setPos))

      var size = 0'u64
      if kind == fkRegular:
        if regularIndex >= planes[0].len:
          dbFail("v2 size column is short")
        for plane in 0 ..< IndexV2SizePlanes:
          size = size or (uint64(uint8(ord(planes[plane][regularIndex]))) shl
            (8 * plane))
        inc regularIndex

      var target = ""
      if kind == fkSymlink:
        let targetLen = int(readVarint(targets, targetPos))
        if targetPos + targetLen > targets.len:
          dbFail("truncated v2 symlink target")
        target = targets[targetPos ..< targetPos + targetLen]
        targetPos += targetLen

      if hitIndex < hits.len and hits[hitIndex] == row:
        inc hitIndex
        if setId < 0 or setId >= sets.len:
          dbFail("invalid v2 package set id")
        var packageNames: seq[string]
        for id in sets[setId]:
          packageNames.add(names[id])
        result.add(FileEntry(
          path: paths[row],
          packages: packageNames,
          size: size,
          kind: kind,
          executable: (flagByte and 4'u8) != 0,
          target: target,
        ))
