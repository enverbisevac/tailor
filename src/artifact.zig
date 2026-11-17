const std = @import("std");
const Io = std.Io;

pub const Kind = enum {
    static_elf,
    dynamic_elf,
    jar,
    node_project,
    python_project,

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .static_elf => "static Linux ELF",
            .dynamic_elf => "dynamic Linux ELF",
            .jar => "Java JAR",
            .node_project => "Node.js project",
            .python_project => "Python project",
        };
    }
};

pub const Architecture = enum {
    amd64,
    arm64,
    arm,
    riscv64,
    x86,
    unknown,

    pub fn label(self: Architecture) []const u8 {
        return switch (self) {
            .amd64 => "amd64",
            .arm64 => "arm64",
            .arm => "arm",
            .riscv64 => "riscv64",
            .x86 => "386",
            .unknown => "unknown",
        };
    }
};

pub const Inspection = struct {
    kind: Kind,
    architecture: Architecture = .unknown,
    is_pie: bool = false,
    has_executable_stack: bool = false,
    node_lock: ?[]const u8 = null,
    python_lock: ?[]const u8 = null,
};

pub const InspectError = error{
    EmptyFile,
    InvalidElf,
    NotPortablePath,
    UnsupportedArtifact,
    UnsupportedElfEndian,
    UnsupportedElfMachine,
    UnsupportedElfType,
    NodeLockInvalid,
    PythonLockMissing,
} || Io.Dir.StatFileError || Io.File.OpenError || Io.File.ReadPositionalError;

/// Inspect without executing the supplied artifact. This matters because input files
/// may be untrusted build outputs.
pub fn inspect(io: Io, path: []const u8) InspectError!Inspection {
    try validatePortablePath(path);
    try rejectSymlinkComponents(io, path);

    const cwd: Io.Dir = .cwd();
    const stat = try cwd.statFile(io, path, .{ .follow_symlinks = false });
    return switch (stat.kind) {
        .file => inspectFile(io, path, stat.size),
        .directory => inspectProject(io, path),
        else => error.UnsupportedArtifact,
    };
}

pub fn validateRegularFile(io: Io, path: []const u8) InspectError!void {
    try validatePortablePath(path);
    try rejectSymlinkComponents(io, path);
    const stat = try Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.UnsupportedArtifact;
}

fn rejectSymlinkComponents(io: Io, path: []const u8) InspectError!void {
    var prefix_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var prefix_len: usize = 0;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        const separator_len: usize = if (prefix_len == 0) 0 else 1;
        const needed = prefix_len + separator_len + component.len;
        if (needed > prefix_buffer.len) return error.NotPortablePath;
        if (separator_len == 1) {
            prefix_buffer[prefix_len] = '/';
            prefix_len += 1;
        }
        @memcpy(prefix_buffer[prefix_len..needed], component);
        prefix_len = needed;

        const stat = try Io.Dir.cwd().statFile(io, prefix_buffer[0..prefix_len], .{ .follow_symlinks = false });
        if (stat.kind == .sym_link) return error.NotPortablePath;
    }
}

fn inspectFile(io: Io, path: []const u8, size: u64) InspectError!Inspection {
    if (size == 0) return error.EmptyFile;

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var header: [64]u8 = undefined;
    const header_len = try file.readPositionalAll(io, &header, 0);
    const bytes = header[0..header_len];

    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) {
        return inspectElf(io, file, size, bytes);
    }

    if (std.ascii.eqlIgnoreCase(std.fs.path.extension(path), ".jar") and
        bytes.len >= 4 and
        (std.mem.eql(u8, bytes[0..4], "PK\x03\x04") or
            std.mem.eql(u8, bytes[0..4], "PK\x05\x06") or
            std.mem.eql(u8, bytes[0..4], "PK\x07\x08")) and
        isExecutableJar(io, file))
    {
        return .{ .kind = .jar };
    }

    return error.UnsupportedArtifact;
}

fn isExecutableJar(io: Io, file: Io.File) bool {
    var file_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &file_buffer);
    var iterator = std.zip.Iterator.init(&file_reader) catch return false;
    var filename_buffer: [std.math.maxInt(u16)]u8 = undefined;

    while (iterator.next() catch return false) |entry| {
        const filename = entry.getFilename(&file_reader, &filename_buffer, .{}) catch return false;
        if (!std.ascii.eqlIgnoreCase(filename, "META-INF/MANIFEST.MF")) continue;
        if (entry.uncompressed_size > 1024 * 1024) return false;

        var manifest: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer manifest.deinit();
        entry.extractTo(&file_reader, &manifest.writer) catch return false;

        var lines = std.mem.splitScalar(u8, manifest.written(), '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (std.ascii.startsWithIgnoreCase(line, "Main-Class:") and line.len > "Main-Class:".len)
                return true;
        }
        return false;
    }
    return false;
}

fn inspectProject(io: Io, path: []const u8) InspectError!Inspection {
    var package_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const package_path = joinPath(&package_path_buffer, path, "package.json") catch
        return error.NotPortablePath;
    if (isRegularFile(io, package_path)) return inspectNodeProject(io, path);
    return inspectPythonProject(io, path);
}

fn isRegularFile(io: Io, path: []const u8) bool {
    validateRegularFile(io, path) catch return false;
    return true;
}

fn inspectNodeProject(io: Io, path: []const u8) InspectError!Inspection {
    var lock_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const lock_path = joinPath(&lock_path_buffer, path, "package-lock.json") catch
        return error.NotPortablePath;
    validateRegularFile(io, lock_path) catch return error.NodeLockInvalid;

    const contents = Io.Dir.cwd().readFileAlloc(io, lock_path, std.heap.page_allocator, .limited(16 * 1024 * 1024)) catch
        return error.NodeLockInvalid;
    defer std.heap.page_allocator.free(contents);
    if (!packageLockIsSafe(contents)) return error.NodeLockInvalid;

    return .{
        .kind = .node_project,
        .node_lock = "package-lock.json",
    };
}

fn inspectPythonProject(io: Io, path: []const u8) InspectError!Inspection {
    const lock_candidates = [_][]const u8{
        "requirements.lock",
        "requirements.txt",
    };

    for (lock_candidates) |name| {
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const joined = joinPath(&path_buffer, path, name) catch return error.NotPortablePath;
        validateRegularFile(io, joined) catch continue;

        const contents = Io.Dir.cwd().readFileAlloc(io, joined, std.heap.page_allocator, .limited(8 * 1024 * 1024)) catch
            return error.PythonLockMissing;
        defer std.heap.page_allocator.free(contents);
        if (!requirementsAreHashLocked(contents)) return error.PythonLockMissing;

        return .{
            .kind = .python_project,
            .python_lock = name,
        };
    }

    return error.PythonLockMissing;
}

fn inspectElf(io: Io, file: Io.File, file_size: u64, header: []const u8) InspectError!Inspection {
    if (header.len < 52 or header[6] != 1) return error.InvalidElf;

    const elf_class = header[4];
    const endian: std.builtin.Endian = switch (header[5]) {
        1 => .little,
        // Big-endian containers exist, but Tailor does not yet have a tested
        // build-and-run path for them. Refusing is safer than a bad image.
        2 => return error.UnsupportedElfEndian,
        else => return error.InvalidElf,
    };

    const machine = std.mem.readInt(u16, header[18..20], endian);
    const architecture: Architecture = switch (machine) {
        3 => .x86,
        40 => .arm,
        62 => .amd64,
        183 => .arm64,
        243 => .riscv64,
        else => return error.UnsupportedElfMachine,
    };

    const elf_type = std.mem.readInt(u16, header[16..18], endian);
    if (elf_type != 2 and elf_type != 3) return error.UnsupportedElfType;

    const entry_point: u64 = switch (elf_class) {
        1 => std.mem.readInt(u32, header[24..28], endian),
        2 => if (header.len >= 64) std.mem.readInt(u64, header[24..32], endian) else return error.InvalidElf,
        else => return error.InvalidElf,
    };
    if (entry_point == 0) return error.UnsupportedElfType;

    const program_offset: u64 = switch (elf_class) {
        1 => std.mem.readInt(u32, header[28..32], endian),
        2 => if (header.len >= 64) std.mem.readInt(u64, header[32..40], endian) else return error.InvalidElf,
        else => return error.InvalidElf,
    };
    const entry_size: u16 = switch (elf_class) {
        1 => std.mem.readInt(u16, header[42..44], endian),
        2 => std.mem.readInt(u16, header[54..56], endian),
        else => unreachable,
    };
    const entry_count: u16 = switch (elf_class) {
        1 => std.mem.readInt(u16, header[44..46], endian),
        2 => std.mem.readInt(u16, header[56..58], endian),
        else => unreachable,
    };

    const minimum_entry_size: u16 = if (elf_class == 1) 32 else 56;
    if (entry_size < minimum_entry_size or entry_count == 0) return error.InvalidElf;

    const table_size = std.math.mul(u64, entry_size, entry_count) catch return error.InvalidElf;
    const table_end = std.math.add(u64, program_offset, table_size) catch return error.InvalidElf;
    if (table_end > file_size) return error.InvalidElf;

    var has_interpreter = false;
    var has_executable_stack = false;
    var entry: [64]u8 = undefined;
    for (0..entry_count) |index| {
        const offset_delta = std.math.mul(u64, entry_size, index) catch return error.InvalidElf;
        const offset = std.math.add(u64, program_offset, offset_delta) catch return error.InvalidElf;
        const read_len = try file.readPositionalAll(io, entry[0..minimum_entry_size], offset);
        if (read_len != minimum_entry_size) return error.InvalidElf;

        const segment_type = std.mem.readInt(u32, entry[0..4], endian);
        if (segment_type == 3) has_interpreter = true; // PT_INTERP
        if (segment_type == 0x6474e551) { // PT_GNU_STACK
            const flags_offset: usize = if (elf_class == 1) 24 else 4;
            const flags = std.mem.readInt(u32, entry[flags_offset..][0..4], endian);
            has_executable_stack = (flags & 0x1) != 0; // PF_X
        }
    }

    return .{
        .kind = if (has_interpreter) .dynamic_elf else .static_elf,
        .architecture = architecture,
        .is_pie = elf_type == 3,
        .has_executable_stack = has_executable_stack,
    };
}

pub fn validatePortablePath(path: []const u8) error{NotPortablePath}!void {
    if (path.len == 0 or std.fs.path.isAbsolute(path)) return error.NotPortablePath;
    if (!std.unicode.utf8ValidateSlice(path) or std.mem.indexOfScalar(u8, path, '\\') != null)
        return error.NotPortablePath;
    for (path) |byte| if (byte < 0x20) return error.NotPortablePath;

    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return error.NotPortablePath;
    }
}

fn joinPath(buffer: []u8, parent: []const u8, child: []const u8) error{NameTooLong}![]const u8 {
    const separator_len: usize = if (parent.len > 0 and parent[parent.len - 1] == '/') 0 else 1;
    const needed = parent.len + separator_len + child.len;
    if (needed > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..parent.len], parent);
    var cursor = parent.len;
    if (separator_len == 1) {
        buffer[cursor] = '/';
        cursor += 1;
    }
    @memcpy(buffer[cursor..needed], child);
    return buffer[0..needed];
}

/// A requirements file is considered locked when every non-option requirement
/// has an exact `==` pin and at least one sha256 hash. This deliberately rejects
/// editable installs, URLs, ranges, and floating versions.
pub fn requirementsAreHashLocked(contents: []const u8) bool {
    // A lockfile must not override the wheel-only installer policy or add
    // source-build hooks through per-requirement options.
    for ([_][]const u8{ "--no-binary", "--config-settings", "--global-option", "--install-option" }) |option| {
        if (std.mem.indexOf(u8, contents, option) != null) return false;
    }
    var pending_requirement = false;
    var pending_hash = false;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line_without_comment = if (std.mem.indexOfScalar(u8, raw_line, '#')) |index|
            raw_line[0..index]
        else
            raw_line;
        const line = std.mem.trim(u8, line_without_comment, " \t\r");
        if (line.len == 0) continue;

        const continued = line[line.len - 1] == '\\';
        const has_hash = hasValidSha256Hash(line);

        if (pending_requirement) {
            if (!isHashOnlyContinuation(line)) return false;
            pending_hash = pending_hash or has_hash;
            if (!continued) {
                if (!pending_hash) return false;
                pending_requirement = false;
                pending_hash = false;
            }
            continue;
        }

        if (std.mem.startsWith(u8, line, "--")) {
            if (!isSafeRequirementsOption(line)) return false;
            continue;
        }
        if (std.mem.startsWith(u8, line, "-") or
            std.mem.indexOf(u8, line, " @ ") != null or
            std.mem.indexOf(u8, line, "://") != null or
            !hasExactPin(line))
        {
            return false;
        }

        if (continued) {
            pending_requirement = true;
            pending_hash = has_hash;
        } else if (!has_hash) {
            return false;
        }
    }

    // A project with no third-party dependencies has nothing to hash. Its empty
    // lockfile is still an explicit, reproducible declaration of that fact.
    return !pending_requirement;
}

/// Accept npm lockfile v2/v3 projects only when every materialized dependency
/// has an exact version and an npm Subresource Integrity digest. The root entry
/// is project metadata and therefore does not need an integrity field.
pub fn packageLockIsSafe(contents: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, contents, .{}) catch
        return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    const lock_version = parsed.value.object.get("lockfileVersion") orelse return false;
    if (lock_version != .integer or (lock_version.integer != 2 and lock_version.integer != 3))
        return false;
    const packages = parsed.value.object.get("packages") orelse return false;
    if (packages != .object) return false;
    const root_package = packages.object.get("") orelse return false;
    if (root_package != .object) return false;

    var iterator = packages.object.iterator();
    while (iterator.next()) |entry| {
        const package_path = entry.key_ptr.*;
        if (package_path.len == 0) continue;
        if (!std.mem.startsWith(u8, package_path, "node_modules/") or entry.value_ptr.* != .object)
            return false;

        const package = entry.value_ptr.object;
        if (package.get("link")) |link| {
            if (link == .bool and link.bool) return false;
        }
        const version = package.get("version") orelse return false;
        if (version != .string or !isExactNpmVersion(version.string)) return false;
        const integrity = package.get("integrity") orelse return false;
        if (integrity != .string or !isStrongNpmIntegrity(integrity.string)) return false;
    }
    return true;
}

fn isExactNpmVersion(version: []const u8) bool {
    if (version.len == 0 or !std.ascii.isDigit(version[0])) return false;
    for (version) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-' or byte == '+'))
            return false;
    }
    return std.mem.indexOfScalar(u8, version, '.') != null;
}

fn isStrongNpmIntegrity(integrity: []const u8) bool {
    const expected_size: usize, const encoded = if (std.mem.startsWith(u8, integrity, "sha512-"))
        .{ 64, integrity["sha512-".len..] }
    else if (std.mem.startsWith(u8, integrity, "sha256-"))
        .{ 32, integrity["sha256-".len..] }
    else
        return false;

    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return false;
    if (decoded_size != expected_size) return false;
    var decoded: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(decoded[0..expected_size], encoded) catch return false;
    return true;
}

fn isHashOnlyContinuation(line: []const u8) bool {
    const without_continuation = std.mem.trimEnd(u8, line, " \t\\");
    var tokens = std.mem.tokenizeAny(u8, without_continuation, " \t");
    var saw_hash = false;
    while (tokens.next()) |token| {
        if (!std.mem.startsWith(u8, token, "--hash=sha256:") or !hasValidSha256Hash(token)) return false;
        saw_hash = true;
    }
    return saw_hash;
}

fn hasExactPin(line: []const u8) bool {
    const requirement_end = std.mem.indexOfAny(u8, line, " \t;\\") orelse line.len;
    const requirement = line[0..requirement_end];
    const pin_index = std.mem.indexOf(u8, requirement, "==") orelse return false;
    if (pin_index == 0 or pin_index + 2 == requirement.len) return false;
    if (std.mem.indexOfPos(u8, requirement, pin_index + 2, "==") != null) return false;
    if (requirement[pin_index - 1] == '<' or requirement[pin_index - 1] == '>' or
        requirement[pin_index - 1] == '!' or requirement[pin_index - 1] == '~' or
        requirement[pin_index - 1] == '=') return false;
    if (requirement[pin_index + 2] == '=' or std.mem.indexOfScalar(u8, requirement[pin_index + 2 ..], '*') != null)
        return false;

    for (requirement[0..pin_index]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '-' or
            byte == '[' or byte == ']' or byte == ',')) return false;
    }
    for (requirement[pin_index + 2 ..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '-' or
            byte == '+' or byte == '!')) return false;
    }
    return true;
}

fn isSafeRequirementsOption(line: []const u8) bool {
    if (std.mem.startsWith(u8, line, "--only-binary"))
        return std.mem.eql(u8, line, "--only-binary :all:") or std.mem.eql(u8, line, "--only-binary=:all:");
    const safe_options = [_][]const u8{
        "--index-url ",
        "--extra-index-url ",
        "--no-index",
        "--prefer-binary",
        "--require-hashes",
    };
    for (safe_options) |option| {
        if (std.mem.startsWith(u8, line, option)) return true;
    }
    return false;
}

fn hasValidSha256Hash(line: []const u8) bool {
    const marker = "--hash=sha256:";
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, line, search_from, marker)) |marker_index| {
        const digest_start = marker_index + marker.len;
        if (digest_start + 64 <= line.len) {
            const digest = line[digest_start..][0..64];
            var valid = true;
            for (digest) |byte| {
                if (!std.ascii.isHex(byte)) {
                    valid = false;
                    break;
                }
            }
            const digest_end = digest_start + 64;
            const delimiter_valid = digest_end == line.len or
                std.ascii.isWhitespace(line[digest_end]) or
                line[digest_end] == '\\';
            if (valid and delimiter_valid) return true;
        }
        search_from = digest_start;
    }
    return false;
}

test "accepts fully hash-locked requirements" {
    const contents =
        \\flask==3.1.2 \\
        \\    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        \\werkzeug==3.1.3 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    ;
    try std.testing.expect(requirementsAreHashLocked(contents));
}

test "rejects floating and unhashed requirements" {
    try std.testing.expect(!requirementsAreHashLocked("flask>=3\n"));
    try std.testing.expect(!requirementsAreHashLocked("flask==3.1.2\n"));
    try std.testing.expect(!requirementsAreHashLocked("git+https://example.invalid/repo\n"));
    try std.testing.expect(!requirementsAreHashLocked("flask==3.1.2 --hash=sha256:not-a-digest\n"));
    try std.testing.expect(!requirementsAreHashLocked("flask==3.* --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
    try std.testing.expect(!requirementsAreHashLocked("flask>=3; python_version=='3.13' --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
    try std.testing.expect(!requirementsAreHashLocked("--trusted-host example.invalid\nflask==3.1.2 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
}

test "accepts an empty Python dependency lock" {
    try std.testing.expect(requirementsAreHashLocked("# This service uses only the standard library.\n"));
}

test "Python locks cannot re-enable source builds" {
    try std.testing.expect(!requirementsAreHashLocked("--only-binary :none:\n"));
    try std.testing.expect(!requirementsAreHashLocked("--no-binary :all:\n"));
    try std.testing.expect(!requirementsAreHashLocked("pkg==1.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --config-settings=hook\n"));
    try std.testing.expect(requirementsAreHashLocked("--only-binary=:all:\n"));
}

test "accepts a package lock with exact integrity-protected dependencies" {
    const contents =
        \\{
        \\  "lockfileVersion": 3,
        \\  "packages": {
        \\    "": { "name": "health" },
        \\    "node_modules/example": {
        \\      "version": "1.2.3",
        \\      "integrity": "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        \\    }
        \\  }
        \\}
    ;
    try std.testing.expect(packageLockIsSafe(contents));
}

test "rejects npm dependencies without integrity metadata" {
    try std.testing.expect(!packageLockIsSafe(
        \\{"lockfileVersion":3,"packages":{"":{},"node_modules/example":{"version":"1.2.3"}}}
    ));
    try std.testing.expect(!packageLockIsSafe(
        \\{"lockfileVersion":3,"packages":{"":{},"node_modules/example":{"version":"latest","integrity":"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="}}}
    ));
}

test "portable paths reject traversal and absolute paths" {
    try validatePortablePath("bin/server");
    try std.testing.expectError(error.NotPortablePath, validatePortablePath("../server"));
    try std.testing.expectError(error.NotPortablePath, validatePortablePath("/tmp/server"));
}
