const std = @import("std");
const Io = std.Io;
const elf = @import("elf.zig");

pub const File = struct { source: []const u8, destination: []const u8, sha256: [64]u8, reason: []const u8, package: ?[]const u8 = null, package_version: ?[]const u8 = null, executable: bool = false, versions: []const []const u8 = &.{} };
pub const Edge = struct { from: []const u8, to: []const u8, reason: []const u8 };
pub const UnresolvedCall = struct { source: []const u8, line: usize, api: []const u8 };

/// Resolve only within an explicitly supplied Linux filesystem. An arena owns
/// all paths and metadata, so the resulting graph remains valid until deinit.
pub const Resolver = struct {
    arena: std.heap.ArenaAllocator,
    root: Io.Dir,
    root_path: []const u8,
    machine: ?u16 = null,
    elf_bits: ?u8 = null,
    abi_flags: ?u32 = null,
    files: std.ArrayList(File) = .empty,
    edges: std.ArrayList(Edge) = .empty,
    unresolved_calls: std.ArrayList(UnresolvedCall) = .empty,
    tree: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, io: Io, root_path: []const u8) !Resolver {
        try @import("artifact.zig").validatePortablePath(root_path);
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        return .{
            .arena = arena,
            .root = try Io.Dir.cwd().openDir(io, root_path, .{ .follow_symlinks = false }),
            .root_path = try arena.allocator().dupe(u8, root_path),
        };
    }

    pub fn deinit(self: *Resolver, io: Io) void {
        self.root.close(io);
        self.arena.deinit();
    }

    pub fn application(self: *Resolver, io: Io, path: []const u8) !void {
        const allocator = self.arena.allocator();
        const bytes = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
        if (!std.mem.startsWith(u8, bytes, "\x7fELF")) return; // JAR/source projects use their runtime profile.
        const metadata = try elf.parse(allocator, bytes);
        self.machine = metadata.machine;
        self.elf_bits = metadata.bits;
        self.abi_flags = metadata.flags;
        try self.closure(io, metadata, "/app/application", 0);
    }

    pub fn command(self: *Resolver, io: Io, name: []const u8) !void {
        try self.commandFrom(io, name, "explicit --exec declaration");
    }

    fn commandFrom(self: *Resolver, io: Io, name: []const u8, origin: []const u8) anyerror!void {
        if (name.len == 0) return error.InvalidCommand;
        for (name) |byte| if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.')) return error.InvalidCommand;
        const allocator = self.arena.allocator();
        for ([_][]const u8{ "/usr/bin", "/bin", "/usr/local/bin" }) |directory| {
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ directory, name });
            _ = self.resolvePath(io, path, 0) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            try self.require(io, path, "external command", origin, 0);
            // Git starts helpers and reads templates at runtime. Preserve them
            // as declared data; recursively inspect every ELF/script helper.
            if (std.mem.eql(u8, name, "git")) {
                try self.commandFrom(io, "git-upload-pack", path);
                try self.commandFrom(io, "git-receive-pack", path);
                try self.commandFrom(io, "git-upload-archive", path);
                try self.optionalTree(io, "/usr/lib/git-core");
                try self.optionalTree(io, "/usr/share/git-core");
                try self.optionalTree(io, "/etc/ssl/certs");
            }
            return;
        }
        return error.UnresolvedCommand;
    }

    pub fn library(self: *Resolver, io: Io, name: []const u8) !void {
        const selected = try self.findLibrary(io, name, null, "/app/application", 0);
        try self.recordEdge("explicit --library declaration", selected, "runtime-loaded library");
    }

    /// Preserve a filtered dpkg inventory so scanners can identify the exact
    /// packages owning copied binaries/libraries instead of guessing from bytes.
    pub fn packageInventory(self: *Resolver, io: Io) !void {
        if (self.files.items.len == 0) return;
        try self.add(io, "/etc/os-release", "distribution identity", 0);
        const allocator = self.arena.allocator();
        const info = self.root.openDir(io, "var/lib/dpkg/info", .{ .iterate = true, .follow_symlinks = false }) catch return error.UnsupportedPackageDatabase;
        defer info.close(io);
        var selected: std.StringHashMap(void) = .init(allocator);
        var iterator = info.iterate();
        while (try iterator.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".list")) continue;
            const list = try info.readFileAlloc(io, entry.name, allocator, .limited(8 * 1024 * 1024));
            const package = try allocator.dupe(u8, entry.name[0 .. entry.name.len - 5]);
            var lines = std.mem.splitScalar(u8, list, '\n');
            while (lines.next()) |path| {
                for (self.files.items) |*file| {
                    const physical = file.source[self.root_path.len..];
                    if (std.mem.eql(u8, path, physical) or std.mem.eql(u8, path, file.destination)) {
                        file.package = package;
                        try selected.put(package, {});
                    }
                }
            }
        }
        for (self.files.items) |file| {
            if (file.executable and file.package == null) {
                std.debug.print("no package owner for native dependency: {s}\n", .{file.destination});
                return error.UnownedNativeDependency;
            }
        }
        const status = try self.root.readFileAlloc(io, "var/lib/dpkg/status", allocator, .limited(32 * 1024 * 1024));
        var filtered: std.Io.Writer.Allocating = .init(allocator);
        var paragraphs = std.mem.splitSequence(u8, status, "\n\n");
        var retained: usize = 0;
        while (paragraphs.next()) |paragraph| {
            var package: ?[]const u8 = null;
            var arch: ?[]const u8 = null;
            var version: ?[]const u8 = null;
            var lines = std.mem.splitScalar(u8, paragraph, '\n');
            while (lines.next()) |line| {
                if (std.mem.startsWith(u8, line, "Package: ")) package = line[9..];
                if (std.mem.startsWith(u8, line, "Architecture: ")) arch = line[14..];
                if (std.mem.startsWith(u8, line, "Version: ")) version = line[9..];
            }
            const name = package orelse continue;
            const qualified = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ name, arch orelse "" });
            if (!selected.contains(name) and !selected.contains(qualified)) continue;
            for (self.files.items) |*file| {
                if (file.package) |owner| if (std.mem.eql(u8, owner, name) or std.mem.eql(u8, owner, qualified)) {
                    file.package_version = version orelse return error.IncompletePackageInventory;
                };
            }
            try filtered.writer.print("{s}\n\n", .{paragraph});
            retained += 1;
            const license = try std.fmt.allocPrint(allocator, "/usr/share/doc/{s}/copyright", .{name});
            self.require(io, license, "package license", name, 0) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
        if (retained != selected.count()) return error.IncompletePackageInventory;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(filtered.written(), &digest, .{});
        const directory = try std.fmt.allocPrint(allocator, "zig-out/tailor-native/{s}", .{std.fmt.bytesToHex(digest, .lower)});
        try Io.Dir.cwd().createDirPath(io, directory);
        const path = try std.fmt.allocPrint(allocator, "{s}/status", .{directory});
        _ = try @import("generated_file.zig").write(.cwd(), allocator, io, path, filtered.written());
        try self.files.append(allocator, .{ .source = path, .destination = "/var/lib/dpkg/status", .sha256 = std.fmt.bytesToHex(digest, .lower), .reason = "filtered package inventory" });
    }

    pub fn materialize(self: *Resolver, io: Io) !void {
        if (self.files.items.len == 0) return;
        const allocator = self.arena.allocator();
        std.mem.sort(File, self.files.items, {}, struct {
            fn less(_: void, a: File, b: File) bool {
                return std.mem.lessThan(u8, a.destination, b.destination);
            }
        }.less);
        // Hash runtime content rather than the location of the supplied sysroot.
        var manifest: std.Io.Writer.Allocating = .init(allocator);
        defer manifest.deinit();
        for (self.files.items) |file| {
            const entry = try std.json.Stringify.valueAlloc(allocator, .{
                .destination = file.destination,
                .sha256 = file.sha256,
                .package = file.package,
                .package_version = file.package_version,
            }, .{});
            defer allocator.free(entry);
            try manifest.writer.writeAll(entry);
            try manifest.writer.writeByte('\n');
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(manifest.written(), &digest, .{});
        const tree = try std.fmt.allocPrint(allocator, "zig-out/tailor-native-root/{s}", .{std.fmt.bytesToHex(digest, .lower)});
        try Io.Dir.cwd().createDirPath(io, tree);
        for (self.files.items) |*file| {
            if (file.destination.len < 2 or file.destination[0] != '/') return error.UnsafeDependency;
            try @import("artifact.zig").validatePortablePath(file.destination[1..]);
            const bytes = try Io.Dir.cwd().readFileAlloc(io, file.source, allocator, .limited(128 * 1024 * 1024));
            defer allocator.free(bytes);
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
            if (!std.mem.eql(u8, &file.sha256, &std.fmt.bytesToHex(hash, .lower))) return error.SourceChanged;
            const target = try std.fmt.allocPrint(allocator, "{s}{s}", .{ tree, file.destination });
            try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(target).?);
            _ = try @import("generated_file.zig").write(.cwd(), allocator, io, target, bytes);
            file.source = target;
        }
        self.tree = tree;
    }

    pub fn discover(self: *Resolver, io: Io, path: []const u8, allow_dynamic: bool) !void {
        try @import("artifact.zig").validatePortablePath(path);
        try self.discoverTree(io, .cwd(), path, path, allow_dynamic, 0);
    }

    fn discoverTree(self: *Resolver, io: Io, parent: Io.Dir, name: []const u8, label: []const u8, allow_dynamic: bool, depth: usize) anyerror!void {
        if (depth > 64) return error.DependencyLimitExceeded;
        const stat = try parent.statFile(io, name, .{ .follow_symlinks = false });
        if (stat.kind == .directory) {
            const directory = try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
            defer directory.close(io);
            var iterator = directory.iterate();
            while (try iterator.next(io)) |entry| {
                if (@import("snapshot.zig").excluded(entry.name)) continue;
                const child = try std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ label, entry.name });
                try self.discoverTree(io, directory, entry.name, child, allow_dynamic, depth + 1);
            }
            return;
        }
        if (stat.kind != .file) return error.UnsafeDependency;
        const extension = std.fs.path.extension(name);
        var supported = false;
        for ([_][]const u8{ ".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".java", ".kt" }) |candidate|
            if (std.mem.eql(u8, extension, candidate)) {
                supported = true;
                break;
            };
        if (!supported) return;
        const bytes = try parent.readFileAlloc(io, name, self.arena.allocator(), .limited(8 * 1024 * 1024));
        const calls = try @import("discovery.zig").scan(self.arena.allocator(), bytes);
        for (calls) |call| {
            const line = std.mem.count(u8, bytes[0..call.offset], "\n") + 1;
            if (call.command) |command_name| {
                std.debug.print("discovered {s}: {s} at {s}:{d}\n", .{ call.api, command_name, label, line });
                const origin = try std.fmt.allocPrint(self.arena.allocator(), "{s}:{d} ({s})", .{ label, line, call.api });
                try self.commandFrom(io, command_name, origin);
            } else {
                try self.unresolved_calls.append(self.arena.allocator(), .{ .source = label, .line = line, .api = call.api });
                if (!allow_dynamic) {
                    std.debug.print("unresolved {s} at {s}:{d}; declare required commands with --exec\n", .{ call.api, label, line });
                    return error.UnresolvedExternalCommand;
                }
            }
        }
    }

    fn optionalTree(self: *Resolver, io: Io, path: []const u8) !void {
        const physical = self.resolvePath(io, path, 0) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        const directory = try self.root.openDir(io, physical, .{ .iterate = true, .follow_symlinks = false });
        defer directory.close(io);
        var iterator = directory.iterate();
        while (try iterator.next(io)) |entry| {
            // Optional foreign-VCS bridges have independent runtime requirements.
            if (std.mem.eql(u8, path, "/usr/lib/git-core") and
                (std.mem.eql(u8, entry.name, "git-p4") or std.mem.eql(u8, entry.name, "git-cvsserver"))) continue;
            const target = try std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ path, entry.name });
            try self.recordEdge(path, target, "command support files");
            if (entry.kind == .directory) try self.optionalTree(io, target) else try self.add(io, target, "command support files", 0);
        }
    }

    fn recordEdge(self: *Resolver, origin: []const u8, destination: []const u8, reason: []const u8) !void {
        for (self.edges.items) |edge| {
            if (std.mem.eql(u8, edge.from, origin) and std.mem.eql(u8, edge.to, destination) and std.mem.eql(u8, edge.reason, reason)) return;
        }
        const allocator = self.arena.allocator();
        try self.edges.append(allocator, .{
            .from = try allocator.dupe(u8, origin),
            .to = try allocator.dupe(u8, destination),
            .reason = reason,
        });
    }

    fn require(self: *Resolver, io: Io, virtual: []const u8, reason: []const u8, origin: []const u8, depth: usize) anyerror!void {
        try self.add(io, virtual, reason, depth);
        try self.recordEdge(origin, virtual, reason);
    }

    fn add(self: *Resolver, io: Io, virtual: []const u8, reason: []const u8, depth: usize) anyerror!void {
        if (depth > 64 or self.files.items.len >= 8192) return error.DependencyLimitExceeded;
        for (self.files.items) |existing| if (std.mem.eql(u8, existing.destination, virtual)) return;
        const allocator = self.arena.allocator();
        const physical = try self.resolvePath(io, virtual, 0);
        const file = try self.root.openFile(io, physical, .{ .follow_symlinks = false });
        defer file.close(io);
        const stat = try file.stat(io);
        if (stat.kind != .file or stat.size > 128 * 1024 * 1024) return error.UnsafeDependency;
        const bytes = try allocator.alloc(u8, @intCast(stat.size));
        defer allocator.free(bytes);
        if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.SourceChanged;
        const is_elf = std.mem.startsWith(u8, bytes, "\x7fELF");
        const is_script = std.mem.startsWith(u8, bytes, "#!");
        if ((std.mem.eql(u8, reason, "DT_NEEDED") or std.mem.eql(u8, reason, "ELF interpreter")) and !is_elf) return error.InvalidElf;
        if (std.mem.eql(u8, reason, "external command") and !is_elf and !is_script) return error.InvalidCommand;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
        if (std.mem.eql(u8, reason, "command support files")) {
            for (self.files.items) |existing| {
                if (std.mem.eql(u8, existing.destination, "/usr/bin/git") and
                    std.mem.eql(u8, &existing.sha256, &std.fmt.bytesToHex(hash, .lower))) return;
            }
        }
        try self.files.append(allocator, .{
            .source = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.root_path, physical }),
            .destination = try allocator.dupe(u8, virtual),
            .sha256 = std.fmt.bytesToHex(hash, .lower),
            .reason = reason,
            .executable = std.mem.startsWith(u8, bytes, "\x7fELF") or std.mem.startsWith(u8, bytes, "#!"),
        });
        if (std.mem.startsWith(u8, bytes, "\x7fELF")) {
            const metadata = try elf.parse(allocator, bytes);
            if (metadata.executable_stack) return error.ExecutableStack;
            const versions = try allocator.alloc([]const u8, metadata.provided_versions.len);
            for (metadata.provided_versions, 0..) |version, i| versions[i] = try allocator.dupe(u8, version);
            self.files.items[self.files.items.len - 1].versions = versions;
            if (self.machine) |machine| {
                if (machine != metadata.machine) return error.IncompatibleArchitecture;
            } else self.machine = metadata.machine;
            if (self.elf_bits) |bits| {
                if (bits != metadata.bits) return error.IncompatibleArchitecture;
            } else self.elf_bits = metadata.bits;
            const mask: u32 = switch (metadata.machine) {
                40 => 0xff000600,
                243 => 6,
                else => 0,
            };
            if (self.abi_flags) |flags| {
                if (flags & mask != metadata.flags & mask) return error.IncompatibleArchitecture;
            } else self.abi_flags = metadata.flags;
            try self.closure(io, metadata, virtual, depth + 1);
        } else if (std.mem.startsWith(u8, bytes, "#!")) {
            const end = std.mem.indexOfAny(u8, bytes[2..], " \t\r\n") orelse return error.InvalidInterpreter;
            const interpreter = bytes[2 .. 2 + end];
            if (interpreter.len == 0 or interpreter[0] != '/' or std.mem.eql(u8, interpreter, "/usr/bin/env"))
                return error.UnresolvedInterpreter;
            try self.require(io, interpreter, "script interpreter", virtual, depth + 1);
        }
    }

    fn closure(self: *Resolver, io: Io, metadata: elf.Metadata, origin: []const u8, depth: usize) anyerror!void {
        if (metadata.interpreter) |interpreter| try self.require(io, interpreter, "ELF interpreter", origin, depth + 1);
        for (metadata.needed) |needed| {
            const selected = try self.findLibrary(io, needed, metadata.runpath orelse metadata.rpath, origin, depth + 1);
            try self.recordEdge(origin, selected, "DT_NEEDED");
            for (metadata.version_needs) |requirement| {
                if (!std.mem.eql(u8, requirement.library, needed)) continue;
                var provided = false;
                for (self.files.items) |file| {
                    if (!std.mem.eql(u8, file.destination, selected)) continue;
                    for (file.versions) |version| if (std.mem.eql(u8, version, requirement.version)) {
                        provided = true;
                        break;
                    };
                }
                if (!provided) {
                    std.debug.print("{s} requires {s} from {s}\n", .{ origin, requirement.version, needed });
                    return error.IncompatibleSymbolVersion;
                }
            }
        }
    }

    fn findLibrary(self: *Resolver, io: Io, name: []const u8, search: ?[]const u8, origin: []const u8, depth: usize) ![]const u8 {
        if (std.mem.indexOfScalar(u8, name, '/') != null) {
            if (name.len == 0 or name[0] != '/') return error.UnsupportedLibraryPath;
            try self.add(io, name, "DT_NEEDED", depth);
            return name;
        }
        if (search) |paths| {
            var iterator = std.mem.splitScalar(u8, paths, ':');
            while (iterator.next()) |directory| {
                var path = directory;
                if (std.mem.startsWith(u8, path, "$ORIGIN")) path = try std.fmt.allocPrint(self.arena.allocator(), "{s}{s}", .{ std.fs.path.dirname(origin).?, path[7..] });
                if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, '$') != null) return error.UnsupportedLibraryPath;
                if (try self.tryLibrary(io, path, name, depth)) |selected| return selected;
            }
        }
        const triplet: []const u8 = switch (self.machine orelse 0) {
            62 => "x86_64-linux-gnu",
            183 => "aarch64-linux-gnu",
            243 => "riscv64-linux-gnu",
            3 => "i386-linux-gnu",
            40 => "arm-linux-gnueabihf",
            else => return error.IncompatibleArchitecture,
        };
        for ([_][]const u8{ "/lib", "/usr/lib" }) |prefix| {
            const directory = try std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ prefix, triplet });
            if (try self.tryLibrary(io, directory, name, depth)) |selected| return selected;
        }
        for ([_][]const u8{ "/lib64", "/usr/lib64", "/lib", "/usr/lib", "/usr/local/lib" }) |directory|
            if (try self.tryLibrary(io, directory, name, depth)) |selected| return selected;
        std.debug.print("unresolved library: {s} required by {s}\n", .{ name, origin });
        return error.UnresolvedLibrary;
    }

    fn tryLibrary(self: *Resolver, io: Io, directory: []const u8, name: []const u8, depth: usize) !?[]const u8 {
        const path = try std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ directory, name });
        _ = self.resolvePath(io, path, 0) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        try self.add(io, path, "DT_NEEDED", depth);
        return path;
    }

    /// Resolve Linux absolute and relative symlinks inside the virtual root,
    /// never using the host's /lib or /usr filesystem for absolute links.
    fn resolvePath(self: *Resolver, io: Io, virtual: []const u8, depth: usize) anyerror![]const u8 {
        if (depth > 32) return error.SymLinkLoop;
        const allocator = self.arena.allocator();
        const normalized = try std.fs.path.resolvePosix(allocator, &.{ "/", virtual });
        var iterator = std.mem.tokenizeScalar(u8, normalized[1..], '/');
        var prefix: std.Io.Writer.Allocating = .init(allocator);
        while (iterator.next()) |component| {
            if (prefix.written().len != 0) try prefix.writer.writeByte('/');
            try prefix.writer.writeAll(component);
            const stat = try self.root.statFile(io, prefix.written(), .{ .follow_symlinks = false });
            if (stat.kind == .sym_link) {
                var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const length = try self.root.readLink(io, prefix.written(), &link_buffer);
                const target = link_buffer[0..length];
                const remainder = iterator.rest();
                const joined = if (std.fs.path.isAbsolutePosix(target))
                    try std.fmt.allocPrint(allocator, "{s}/{s}", .{ target, remainder })
                else
                    try std.fmt.allocPrint(allocator, "/{s}/{s}/{s}", .{ std.fs.path.dirname(prefix.written()) orelse "", target, remainder });
                return self.resolvePath(io, joined, depth + 1);
            }
        }
        return prefix.toOwnedSlice();
    }
};

test "sysroot symlinks resolve internally and cycles are rejected" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "usr/lib");
    try tmp.dir.writeFile(io, .{ .sub_path = "usr/lib/example", .data = "library" });
    try tmp.dir.symLink(io, "/usr/lib", "lib", .{ .is_directory = true });
    try tmp.dir.symLink(io, "/loop", "loop", .{});
    var resolver: Resolver = .{
        .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
        .root = try tmp.dir.openDir(io, ".", .{}),
        .root_path = ".",
    };
    defer resolver.deinit(io);
    try std.testing.expectEqualStrings("usr/lib/example", try resolver.resolvePath(io, "/lib/example", 0));
    try std.testing.expectError(error.SymLinkLoop, resolver.resolvePath(io, "/loop", 0));
}
