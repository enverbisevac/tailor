const std = @import("std");
const Io = std.Io;
const artifact = @import("artifact.zig");

pub const Entry = struct { path: []const u8, sha256: [64]u8, size: u64 };

/// A private, curated copy is the only source consumed by scans and Docker.
pub const Snapshot = struct {
    path: []const u8,
    dir: Io.Dir,
    entries: std.ArrayList(Entry) = .empty,
    total_bytes: u64 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, io: Io) !Snapshot {
        var nonce: [16]u8 = undefined;
        try io.randomSecure(&nonce);
        const path = try std.fmt.allocPrint(allocator, ".tailor-context-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        errdefer allocator.free(path);
        try Io.Dir.cwd().createDir(io, path, .default_dir);
        errdefer Io.Dir.cwd().deleteDir(io, path) catch {};
        return .{ .path = path, .dir = try Io.Dir.cwd().openDir(io, path, .{}), .allocator = allocator };
    }

    pub fn deinit(self: *Snapshot, io: Io) void {
        self.dir.close(io);
        Io.Dir.cwd().deleteTree(io, self.path) catch {};
        for (self.entries.items) |entry| self.allocator.free(entry.path);
        self.entries.deinit(self.allocator);
        self.allocator.free(self.path);
    }

    pub fn add(self: *Snapshot, io: Io, path: []const u8) !void {
        try artifact.validatePortablePath(path);
        // Validate every source component, including directories, before opening.
        var parts = std.mem.splitScalar(u8, path, '/');
        var prefix: std.Io.Writer.Allocating = .init(self.allocator);
        defer prefix.deinit();
        while (parts.next()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            if (prefix.written().len > 0) try prefix.writer.writeByte('/');
            try prefix.writer.writeAll(part);
            const stat = try Io.Dir.cwd().statFile(io, prefix.written(), .{ .follow_symlinks = false });
            if (stat.kind == .sym_link) return error.UnsafeSnapshotEntry;
        }
        try self.copy(io, .cwd(), path, path, 0);
    }

    fn copy(self: *Snapshot, io: Io, source: Io.Dir, name: []const u8, destination: []const u8, depth: usize) anyerror!void {
        if (depth > 64 or self.entries.items.len >= 100_000) return error.SnapshotLimitExceeded;
        const stat = try source.statFile(io, name, .{ .follow_symlinks = false });
        switch (stat.kind) {
            .directory => {
                try self.dir.createDirPath(io, destination);
                const child = try source.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
                defer child.close(io);
                var iterator = child.iterate();
                while (try iterator.next(io)) |entry| {
                    if (excluded(entry.name)) continue;
                    const target = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ destination, entry.name });
                    defer self.allocator.free(target);
                    try self.copy(io, child, entry.name, target, depth + 1);
                }
            },
            .file => {
                // Bound memory and context size; do not follow replaced symlinks.
                if (stat.size > 128 * 1024 * 1024 or self.total_bytes + stat.size > 512 * 1024 * 1024)
                    return error.SnapshotLimitExceeded;
                const input = try source.openFile(io, name, .{ .follow_symlinks = false });
                defer input.close(io);
                const opened = try input.stat(io);
                if (opened.kind != .file or opened.size != stat.size or opened.inode != stat.inode)
                    return error.SourceChanged;
                const bytes = try self.allocator.alloc(u8, @intCast(stat.size));
                defer self.allocator.free(bytes);
                if (try input.readPositionalAll(io, bytes, 0) != bytes.len) return error.SourceChanged;
                const after = try input.stat(io);
                if (after.size != opened.size or !std.meta.eql(after.mtime, opened.mtime)) return error.SourceChanged;
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
                // Includes may refer to an already snapshotted project file.
                for (self.entries.items) |existing| {
                    if (std.mem.eql(u8, existing.path, destination)) {
                        if (!std.mem.eql(u8, &existing.sha256, &std.fmt.bytesToHex(digest, .lower))) return error.SourceChanged;
                        return;
                    }
                }
                if (std.fs.path.dirname(destination)) |parent| try self.dir.createDirPath(io, parent);
                const output = try self.dir.createFile(io, destination, .{ .exclusive = true, .permissions = opened.permissions });
                defer output.close(io);
                try output.writeStreamingAll(io, bytes);
                try self.entries.append(self.allocator, .{
                    .path = try self.allocator.dupe(u8, destination),
                    .sha256 = std.fmt.bytesToHex(digest, .lower),
                    .size = stat.size,
                });
                self.total_bytes += stat.size;
            },
            else => return error.UnsafeSnapshotEntry,
        }
    }

    pub fn joined(self: Snapshot, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.path, path });
    }

    pub fn writeManifest(self: Snapshot, io: Io) !void {
        const json = try std.json.Stringify.valueAlloc(self.allocator, .{ .schema_version = 1, .files = self.entries.items }, .{ .whitespace = .indent_2 });
        defer self.allocator.free(json);
        try self.dir.writeFile(io, .{ .sub_path = "tailor-inputs.json", .data = json });
        Io.Dir.cwd().createDir(io, ".tailor-reports", .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const reports = try Io.Dir.cwd().openDir(io, ".tailor-reports", .{ .follow_symlinks = false });
        defer reports.close(io);
        const filename = try std.fmt.allocPrint(self.allocator, "{s}-inputs.json", .{self.path[1..]});
        defer self.allocator.free(filename);
        try reports.writeFile(io, .{ .sub_path = filename, .data = json, .flags = .{ .exclusive = true } });
    }
};

pub fn excluded(name: []const u8) bool {
    if (std.mem.startsWith(u8, name, ".tailor-") or std.mem.startsWith(u8, name, ".env")) return true;
    for ([_][]const u8{ ".git", ".aws", ".ssh", ".npmrc", ".pypirc", ".netrc", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".zig-cache", "zig-out", "Dockerfile", ".dockerignore" }) |entry|
        if (std.mem.eql(u8, name, entry)) return true;
    for ([_][]const u8{ ".key", ".pem", ".p12", ".pfx", ".pyc" }) |extension|
        if (std.ascii.endsWithIgnoreCase(name, extension)) return true;
    return false;
}

test "snapshot exclusions remove credentials and development environments" {
    for ([_][]const u8{ ".env", ".env.production", ".aws", "node_modules", "server.key", "__pycache__", ".tailor-context-abc" }) |name|
        try std.testing.expect(excluded(name));
    try std.testing.expect(!excluded("server.js"));
    try std.testing.expect(!excluded("dist"));
}

test "snapshot retains scanned bytes when original files later change" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var source = std.testing.tmpDir(.{});
    defer source.cleanup();
    try source.dir.createDir(io, "app", .default_dir);
    try source.dir.writeFile(io, .{ .sub_path = "app/server.py", .data = "original" });
    try source.dir.writeFile(io, .{ .sub_path = "app/.env", .data = "SECRET=hidden" });
    var context = try Snapshot.init(allocator, io);
    defer context.deinit(io);
    try context.copy(io, source.dir, "app", "app", 0);
    try source.dir.writeFile(io, .{ .sub_path = "app/server.py", .data = "changed" });
    const copied = try context.dir.readFileAlloc(io, "app/server.py", allocator, .limited(1024));
    defer allocator.free(copied);
    try std.testing.expectEqualStrings("original", copied);
    try std.testing.expectEqual(@as(usize, 1), context.entries.items.len);
}
