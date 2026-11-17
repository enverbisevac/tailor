const std = @import("std");
const Io = std.Io;

pub const Status = enum {
    created,
    updated,
    unchanged,
};

/// Create a missing generated file or update an existing regular file in
/// place. Identical content is left untouched, preserving its modification
/// time. Symlinks and non-regular destinations are rejected.
pub fn write(
    dir: Io.Dir,
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    contents: []const u8,
) !Status {
    try @import("artifact.zig").validatePortablePath(path);
    try validateParentDirectories(dir, io, path);

    const destination = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return create(dir, io, path, contents),
        else => return err,
    };
    if (destination.kind != .file or destination.nlink != 1) return error.UnsafeOutputPath;

    const file = dir.openFile(io, path, .{
        .mode = .read_write,
        .follow_symlinks = false,
        .lock = .exclusive,
    }) catch |err| switch (err) {
        error.FileNotFound, error.SymLinkLoop => return error.UnsafeOutputPath,
        else => return err,
    };
    defer file.close(io);

    const opened = try file.stat(io);
    if (opened.kind != .file or opened.nlink != 1 or opened.inode != destination.inode)
        return error.UnsafeOutputPath;

    const length = try file.length(io);
    if (length == contents.len) {
        const existing = try allocator.alloc(u8, contents.len);
        defer allocator.free(existing);
        const read = try file.readPositionalAll(io, existing, 0);
        if (read != existing.len) return error.ConcurrentModification;
        if (std.mem.eql(u8, existing, contents)) return .unchanged;
    }

    // Positional writes plus setLength update the open file itself rather than
    // replacing its directory entry, preserving ownership and permissions.
    try file.writePositionalAll(io, contents, 0);
    try file.setLength(io, contents.len);
    return .updated;
}

/// Compare canonical paths so aliases such as ./server cannot overwrite input.
pub fn rejectInputAlias(dir: Io.Dir, io: Io, output: []const u8, input: []const u8) !void {
    const output_file = dir.openFile(io, output, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer output_file.close(io);
    var output_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var input_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const output_len = try dir.realPathFile(io, output, &output_buffer);
    const input_len = try dir.realPathFile(io, input, &input_buffer);
    if (std.mem.eql(u8, output_buffer[0..output_len], input_buffer[0..input_len]))
        return error.OutputReplacesInput;
}

fn create(dir: Io.Dir, io: Io, path: []const u8, contents: []const u8) !Status {
    const file = dir.createFile(io, path, .{
        .exclusive = true,
        .lock = .exclusive,
    }) catch |err| switch (err) {
        // A destination that appeared between stat and create is not followed.
        error.PathAlreadyExists => return error.ConcurrentModification,
        else => return err,
    };
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
    return .created;
}

fn validateParentDirectories(dir: Io.Dir, io: Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0 or std.mem.eql(u8, parent, ".")) return;

    var prefix_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var prefix_len: usize = 0;
    var components = std.mem.splitScalar(u8, parent, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        const separator_len: usize = if (prefix_len == 0) 0 else 1;
        const needed = prefix_len + separator_len + component.len;
        if (needed > prefix_buffer.len) return error.UnsafeOutputPath;
        if (separator_len == 1) {
            prefix_buffer[prefix_len] = '/';
            prefix_len += 1;
        }
        @memcpy(prefix_buffer[prefix_len..needed], component);
        prefix_len = needed;

        const stat = try dir.statFile(io, prefix_buffer[0..prefix_len], .{ .follow_symlinks = false });
        if (stat.kind != .directory) return error.UnsafeOutputPath;
    }
}

test "generated files are created, updated in place, and skipped when unchanged" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectEqual(Status.created, try write(tmp.dir, allocator, io, "Dockerfile", "first\n"));
    const before = try tmp.dir.statFile(io, "Dockerfile", .{});

    try std.testing.expectEqual(Status.unchanged, try write(tmp.dir, allocator, io, "Dockerfile", "first\n"));
    try std.testing.expectEqual(Status.updated, try write(tmp.dir, allocator, io, "Dockerfile", "second version\n"));

    const after = try tmp.dir.statFile(io, "Dockerfile", .{});
    try std.testing.expectEqual(before.inode, after.inode);
    const actual = try tmp.dir.readFileAlloc(io, "Dockerfile", allocator, .limited(1024));
    defer allocator.free(actual);
    try std.testing.expectEqualStrings("second version\n", actual);
}

test "generated files reject symlink destinations and parents" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = "keep\n" });
    try tmp.dir.symLink(io, "target", "Dockerfile", .{});
    try std.testing.expectError(error.UnsafeOutputPath, write(tmp.dir, allocator, io, "Dockerfile", "replace\n"));

    try tmp.dir.createDir(io, "real", .default_dir);
    try tmp.dir.symLink(io, "real", "linked", .{});
    try std.testing.expectError(error.UnsafeOutputPath, write(tmp.dir, allocator, io, "linked/Dockerfile", "replace\n"));

    const target = try tmp.dir.readFileAlloc(io, "target", allocator, .limited(1024));
    defer allocator.free(target);
    try std.testing.expectEqualStrings("keep\n", target);
}

test "input aliases and hard-linked outputs are rejected without modifying input" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "server", .data = "executable bytes" });
    try std.testing.expectError(error.OutputReplacesInput, rejectInputAlias(tmp.dir, io, "./server", "server"));
    try tmp.dir.hardLink("server", tmp.dir, "Dockerfile", io, .{});
    try std.testing.expectError(error.UnsafeOutputPath, write(tmp.dir, allocator, io, "Dockerfile", "replacement"));
    const actual = try tmp.dir.readFileAlloc(io, "server", allocator, .limited(1024));
    defer allocator.free(actual);
    try std.testing.expectEqualStrings("executable bytes", actual);
}
