//! Bounded coverage-guided parser targets. No subprocesses or network access.
const std = @import("std");
const artifact = @import("artifact.zig");
const elf = @import("elf.zig");
const reports = @import("scan_report.zig");

const prefix = "\xff\xff\xff\xff"; // Smith slice length is clamped to remaining seed bytes.
const minimal_elf: [64]u8 = blk: {
    var bytes: [64]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    bytes[16] = 2;
    bytes[18] = 183;
    bytes[54] = 56;
    break :blk bytes;
};

// A valid dynamic ELF seed reaches string tables and GNU version records.
const dynamic_elf: [512]u8 = blk: {
    var bytes: [512]u8 = @splat(0);
    @memcpy(bytes[0..64], &minimal_elf);
    put64(&bytes, 32, 64);
    bytes[56] = 3;
    bytes[64] = 1; // PT_LOAD.
    put64(&bytes, 80, 0x1000);
    put64(&bytes, 96, 512);
    bytes[120] = 2; // PT_DYNAMIC.
    put64(&bytes, 128, 256);
    put64(&bytes, 152, 96);
    bytes[176] = 3; // PT_INTERP.
    put64(&bytes, 184, 448);
    put64(&bytes, 208, 11);
    put64(&bytes, 256, 5);
    put64(&bytes, 264, 0x1180);
    put64(&bytes, 272, 10);
    put64(&bytes, 280, 23);
    put64(&bytes, 288, 1);
    put64(&bytes, 296, 1);
    put64(&bytes, 304, 0x6ffffffe);
    put64(&bytes, 312, 0x11a0);
    put64(&bytes, 320, 0x6fffffff);
    put64(&bytes, 328, 1);
    @memcpy(bytes[384..407], "\x00libc.so.6\x00GLIBC_2.2.5\x00");
    bytes[416] = 1;
    bytes[418] = 1;
    bytes[420] = 1;
    bytes[424] = 16;
    bytes[440] = 11;
    @memcpy(bytes[448..459], "/lib/ld.so\x00");
    break :blk bytes;
};

fn put64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

test "fuzz ELF metadata" {
    try std.testing.fuzz({}, fuzzElf, .{ .corpus = &.{ prefix ++ minimal_elf, prefix ++ dynamic_elf, prefix ++ "\x7fELF\x02\x01\x01" } });
}

fn fuzzElf(_: void, smith: *std.testing.Smith) !void {
    var buffer: [16 * 1024]u8 = undefined;
    const bytes = buffer[0..smith.slice(&buffer)];
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = elf.parse(arena.allocator(), bytes) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
}

test "fuzz dependency locks" {
    try std.testing.fuzz({}, fuzzLocks, .{ .corpus = &.{
        prefix ++ "{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"}}}",
        prefix ++ "idna==3.20 --hash=sha256:ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c\n",
        prefix ++ "--no-binary=:all:\n",
    } });
}

fn fuzzLocks(_: void, smith: *std.testing.Smith) !void {
    var buffer: [8 * 1024]u8 = undefined;
    const bytes = buffer[0..smith.slice(&buffer)];
    _ = artifact.requirementsAreHashLocked(bytes);
    _ = artifact.packageLockIsSafe(bytes);
}

test "fuzz scanner reports" {
    try std.testing.fuzz({}, fuzzReports, .{ .corpus = &.{
        prefix ++ "{\"SchemaVersion\":2,\"Results\":[{\"Packages\":[{\"Name\":\"idna\"}],\"Vulnerabilities\":null}]}",
        prefix ++ "{\"results\":[{\"packages\":[{\"package\":{\"name\":\"idna\",\"version\":\"3.20\"}}]}]}",
        prefix ++ "{\"matches\":[],\"descriptor\":{\"db\":{\"status\":{\"valid\":true,\"built\":\"2026-11-17T00:00:00Z\"}}}}",
    } });
}

fn fuzzReports(_: void, smith: *std.testing.Smith) !void {
    var buffer: [8 * 1024]u8 = undefined;
    const bytes = buffer[0..smith.slice(&buffer)];
    var parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{}) catch return;
    defer parsed.deinit();
    for ([_][]const u8{ "trivy", "grype", "osv-scanner" }) |scanner| {
        _ = reports.summarize(scanner, parsed.value) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => continue,
        };
    }
    reports.validateGrypeFreshness(parsed.value, 1794873600) catch {};
}
