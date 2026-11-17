const std = @import("std");
const artifact = @import("artifact.zig");

pub const Probe = struct {
    language: []const u8,
    version: []const u8,
    arch: []const u8,
    abi: []const u8,
    libc: []const u8,
};

pub fn validate(allocator: std.mem.Allocator, io: std.Io, kind: artifact.Kind, base: ?[]const u8, builder: ?[]const u8) !void {
    switch (kind) {
        .python_project, .node_project => {
            const runtime = try probe(allocator, io, kind, base.?, false);
            defer runtime.deinit();
            const build = try probe(allocator, io, kind, builder.?, true);
            defer build.deinit();
            try compatible(build.value, runtime.value);
        },
        .jar => {
            const result = try runProbe(allocator, io, base.?, "java", &.{"-version"});
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);
        },
        else => {},
    }
}

fn probe(allocator: std.mem.Allocator, io: std.Io, kind: artifact.Kind, image: []const u8, builder: bool) !std.json.Parsed(Probe) {
    const python = "import json,platform,sys,sysconfig;print(json.dumps(dict(language='python',version=str(sys.version_info.major)+'.'+str(sys.version_info.minor),arch=platform.machine(),abi=sysconfig.get_config_var('SOABI') or '',libc=platform.libc_ver()[1])))";
    const node = "console.log(JSON.stringify({language:'node',version:process.versions.node.split('.')[0],arch:process.arch,abi:process.versions.modules,libc:process.report.getReport().header.glibcVersionRuntime||''}))";
    const executable = if (kind == .python_project) "python" else if (builder) "node" else "/nodejs/bin/node";
    const args: []const []const u8 = if (kind == .python_project) &.{ "-I", "-c", python } else &.{ "-e", node };
    const result = try runProbe(allocator, io, image, executable, args);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return std.json.parseFromSlice(Probe, allocator, result.stdout, .{ .allocate = .alloc_always }) catch error.InvalidRuntimeProbe;
}

fn runProbe(allocator: std.mem.Allocator, io: std.Io, image: []const u8, executable: []const u8, args: []const []const u8) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--memory", "256m", "--cpus", "1", "--user", "65532:65532", "--entrypoint", executable, image });
    try argv.appendSlice(allocator, args);
    const result = try std.process.run(allocator, io, .{ .argv = argv.items, .stdout_limit = .limited(64 * 1024), .stderr_limit = .limited(64 * 1024), .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } } });
    switch (result.term) {
        .exited => |code| if (code == 0) return result,
        else => {},
    }
    std.debug.print("runtime probe failed: {s}\n", .{result.stderr});
    allocator.free(result.stdout);
    allocator.free(result.stderr);
    return error.IncompatibleRuntime;
}

pub fn compatible(builder: Probe, runtime: Probe) !void {
    if (!std.mem.eql(u8, builder.language, runtime.language) or
        !std.mem.eql(u8, builder.version, runtime.version) or
        !std.mem.eql(u8, builder.arch, runtime.arch) or
        builder.abi.len == 0 or !std.mem.eql(u8, builder.abi, runtime.abi)) return error.IncompatibleRuntime;
    // Unknown libc is not proof of compatibility for native dependencies.
    if (builder.libc.len == 0 or runtime.libc.len == 0) return error.UnsupportedLibc;
    const build_version = try libcVersion(builder.libc);
    const run_version = try libcVersion(runtime.libc);
    if (build_version[0] != run_version[0] or build_version[1] > run_version[1]) return error.IncompatibleRuntime;
}

fn libcVersion(value: []const u8) ![2]u32 {
    var parts = std.mem.splitScalar(u8, value, '.');
    return .{
        std.fmt.parseInt(u32, parts.next() orelse return error.UnsupportedLibc, 10) catch return error.UnsupportedLibc,
        std.fmt.parseInt(u32, parts.next() orelse return error.UnsupportedLibc, 10) catch return error.UnsupportedLibc,
    };
}

test "native runtime compatibility rejects ABI and older libc" {
    const build: Probe = .{ .language = "python", .version = "3.13", .arch = "aarch64", .abi = "cpython-313-aarch64-linux-gnu", .libc = "2.41" };
    try compatible(build, build);
    var runtime = build;
    runtime.version = "3.12";
    try std.testing.expectError(error.IncompatibleRuntime, compatible(build, runtime));
    runtime = build;
    runtime.libc = "2.40";
    try std.testing.expectError(error.IncompatibleRuntime, compatible(build, runtime));
    runtime.libc = "2.42";
    try compatible(build, runtime);
    runtime.arch = "x86_64";
    try std.testing.expectError(error.IncompatibleRuntime, compatible(build, runtime));
}
