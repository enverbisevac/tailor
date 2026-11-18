const std = @import("std");
const artifact = @import("artifact.zig");
const snapshot = @import("snapshot.zig");
const dependencies = @import("dependencies.zig");
const dockerfile = @import("dockerfile.zig");

pub const default_http_probe = "curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93";
pub const Smoke = struct {
    command: []const []const u8 = &.{},
    http_path: ?[]const u8 = null,
    port: u16 = 8080,
    timeout_seconds: u16 = 30,
    probe_image: ?[]const u8 = null,
};

pub const Config = struct {
    input: []const u8,
    platform: []const u8,
    base: ?[]const u8 = null,
    builder_base: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    source: ?[]const u8 = null,
    commands: []const []const u8 = &.{},
    libraries: []const []const u8 = &.{},
    extra_files: []const dockerfile.ExtraFile = &.{},
    native_resolution: bool = false,
    smoke: Smoke = .{},
    attest: bool = false,
};

pub const Native = struct { destination: []const u8, sha256: [64]u8, package: ?[]const u8, version: ?[]const u8 };
pub const Plan = struct {
    schema_version: u32,
    generator_version: []const u8,
    config: Config,
    files: []const snapshot.Entry,
    native_files: []const Native,
    dockerfile_sha256: [64]u8,
};

pub fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn target(architecture: artifact.Architecture, requested: ?[]const u8, required: bool) !?[]const u8 {
    const detected: ?[]const u8 = switch (architecture) {
        .amd64 => "linux/amd64",
        .arm64 => "linux/arm64",
        .arm => "linux/arm/v7",
        .riscv64 => "linux/riscv64",
        .x86 => "linux/386",
        .unknown => null,
    };
    if (requested) |value| {
        var valid = false;
        for ([_][]const u8{ "linux/amd64", "linux/arm64", "linux/arm/v7", "linux/riscv64", "linux/386" }) |allowed|
            if (std.mem.eql(u8, value, allowed)) {
                valid = true;
                break;
            };
        if (!valid) return error.InvalidPlatform;
        if (detected) |actual| if (!std.mem.eql(u8, actual, value)) return error.PlatformMismatch;
        return value;
    }
    if (required and detected == null) return error.PlatformRequired;
    return detected;
}

pub fn render(allocator: std.mem.Allocator, version: []const u8, config: Config, entries: []const snapshot.Entry, native_files: []const dependencies.File, contents: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var normalized = config;
    if (normalized.smoke.http_path != null and normalized.smoke.probe_image == null) normalized.smoke.probe_image = default_http_probe;
    normalized.input = try snapshot.normalizePath(a, config.input);
    if (config.source) |source| normalized.source = try snapshot.normalizePath(a, source);
    normalized.commands = try sorted(a, config.commands);
    normalized.libraries = try sorted(a, config.libraries);
    const extras = try a.dupe(dockerfile.ExtraFile, config.extra_files);
    for (extras) |*extra| extra.source = try snapshot.normalizePath(a, extra.source);
    normalized.extra_files = extras;
    const files = try a.dupe(snapshot.Entry, entries);
    for (files) |*file| file.path = try snapshot.normalizePath(a, file.path);
    std.mem.sort(snapshot.Entry, files, {}, struct {
        fn less(_: void, x: snapshot.Entry, y: snapshot.Entry) bool {
            return std.mem.lessThan(u8, x.path, y.path);
        }
    }.less);
    const native = try a.alloc(Native, native_files.len);
    for (native_files, native) |file, *out| out.* = .{ .destination = file.destination, .sha256 = file.sha256, .package = file.package, .version = file.package_version };
    std.mem.sort(Native, native, {}, struct {
        fn less(_: void, x: Native, y: Native) bool {
            return std.mem.lessThan(u8, x.destination, y.destination);
        }
    }.less);
    return std.json.Stringify.valueAlloc(allocator, Plan{
        .schema_version = 1,
        .generator_version = version,
        .config = normalized,
        .files = files,
        .native_files = native,
        .dockerfile_sha256 = hash(contents),
    }, .{ .whitespace = .indent_2 });
}

fn sorted(allocator: std.mem.Allocator, values: []const []const u8) ![][]const u8 {
    const result = try allocator.dupe([]const u8, values);
    std.mem.sort([]const u8, result, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.less);
    return result;
}

pub fn verify(allocator: std.mem.Allocator, saved: []const u8, current: []const u8) !void {
    var parsed = std.json.parseFromSlice(Plan, allocator, saved, .{}) catch return error.InvalidLockfile;
    defer parsed.deinit();
    if (parsed.value.schema_version != 1) return error.InvalidLockfile;
    const canonical = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, current)) return error.LockMismatch;
}

test "locks reject input, target and native resolution changes" {
    const a = std.testing.allocator;
    const entry: snapshot.Entry = .{ .path = "app", .sha256 = hash("old"), .size = 3, .mode = 0o755 };
    const original = try render(a, "test", .{ .input = "app", .platform = "linux/amd64" }, &.{entry}, &.{}, "Dockerfile");
    defer a.free(original);
    try verify(a, original, original);
    var changed = entry;
    changed.sha256 = hash("new");
    const updated = try render(a, "test", .{ .input = "app", .platform = "linux/amd64" }, &.{changed}, &.{}, "Dockerfile");
    defer a.free(updated);
    try std.testing.expectError(error.LockMismatch, verify(a, original, updated));
    try std.testing.expectError(error.PlatformMismatch, target(.amd64, "linux/arm64", true));
    try std.testing.expectError(error.PlatformRequired, target(.unknown, null, true));
}

test "native lock identity ignores host location but rejects package version changes" {
    const a = std.testing.allocator;
    var native: dependencies.File = .{ .source = "sysroot/lib/libc.so.6", .destination = "/lib/libc.so.6", .sha256 = hash("library"), .reason = "needed", .package = "libc6", .package_version = "2.36" };
    const config: Config = .{ .input = "app", .platform = "linux/amd64", .native_resolution = true };
    const original = try render(a, "test", config, &.{}, &.{native}, "Dockerfile");
    defer a.free(original);
    native.source = "relocated/lib/libc.so.6";
    const relocated = try render(a, "test", config, &.{}, &.{native}, "Dockerfile");
    defer a.free(relocated);
    try verify(a, original, relocated);
    native.package_version = "2.37";
    const changed = try render(a, "test", config, &.{}, &.{native}, "Dockerfile");
    defer a.free(changed);
    try std.testing.expectError(error.LockMismatch, verify(a, original, changed));
    var policy = config;
    policy.smoke.http_path = "/health";
    const gated = try render(a, "test", policy, &.{}, &.{native}, "Dockerfile");
    defer a.free(gated);
    try std.testing.expectError(error.LockMismatch, verify(a, changed, gated));
}
