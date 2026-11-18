const std = @import("std");
const Io = std.Io;
const Options = @import("lockfile.zig").Smoke;

pub const Result = struct { mode: enum { not_requested, command, http } = .not_requested, passed: ?bool = null, http_status: ?u16 = null };

pub fn validate(options: Options) !void {
    if (options.timeout_seconds == 0 or options.timeout_seconds > 300 or options.port == 0) return error.InvalidSmokeOptions;
    if (options.command.len > 0 and options.http_path != null) return error.InvalidSmokeOptions;
    if (options.command.len > 64) return error.InvalidSmokeOptions;
    for (options.command) |arg| if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidSmokeOptions;
    if (options.command.len > 0 and options.command[0].len == 0) return error.InvalidSmokeOptions;
    if (options.http_path) |path| {
        _ = @import("dockerfile.zig").requirePinnedBase(options.probe_image orelse @import("lockfile.zig").default_http_probe) catch return error.InvalidSmokeOptions;
        if (path.len == 0 or path.len > 1024 or path[0] != '/') return error.InvalidSmokeOptions;
        for (path) |byte| if (byte <= 0x20 or byte >= 0x7f) return error.InvalidSmokeOptions;
    }
}

pub fn run(allocator: std.mem.Allocator, io: Io, image_id: []const u8, options: Options, platform: ?[]const u8) !Result {
    try validate(options);
    if (options.command.len == 0 and options.http_path == null) return .{};
    var nonce: [16]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try std.fmt.allocPrint(allocator, "tailor-smoke-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    defer allocator.free(name);
    defer cleanup(allocator, io, &.{ "docker", "rm", "--force", name });
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        "docker",                         "run",       "--name",   name,   "--read-only", "--cap-drop", "ALL",    "--security-opt", "no-new-privileges:true",
        "--pids-limit",                   "128",       "--memory", "256m", "--cpus",      "1",          "--user", "65532:65532",    "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=32m", "--network", "none",
    });
    try argv.appendSlice(allocator, &.{ "--log-driver", "none" });
    if (platform) |value| try argv.appendSlice(allocator, &.{ "--platform", value });
    if (options.http_path != null) {
        try argv.appendSlice(allocator, &.{ "--detach", image_id });
        try checked(allocator, io, argv.items, 30);
    } else {
        try argv.appendSlice(allocator, &.{ "--detach", "--entrypoint", options.command[0], image_id });
        try argv.appendSlice(allocator, options.command[1..]);
        try checked(allocator, io, argv.items, 30);
        if (try waitForExit(allocator, io, name, options.timeout_seconds) != 0) return error.SmokeFailed;
        return .{ .mode = .command, .passed = true };
    }
    const probe_image = options.probe_image orelse @import("lockfile.zig").default_http_probe;
    const inspected = process(allocator, io, &.{ "docker", "image", "inspect", probe_image }, 10) catch return error.SmokeFailed;
    defer allocator.free(inspected.stdout);
    defer allocator.free(inspected.stderr);
    if (!succeeded(inspected)) try checked(allocator, io, &.{ "docker", "pull", probe_image }, 300);
    const probe_name = try std.fmt.allocPrint(allocator, "{s}-probe", .{name});
    defer allocator.free(probe_name);
    defer cleanup(allocator, io, &.{ "docker", "rm", "--force", probe_name });
    const network = try std.fmt.allocPrint(allocator, "container:{s}", .{name});
    defer allocator.free(network);
    const timeout = try std.fmt.allocPrint(allocator, "{d}", .{options.timeout_seconds});
    defer allocator.free(timeout);
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}{s}", .{ options.port, options.http_path.? });
    defer allocator.free(url);
    try checked(allocator, io, &.{
        "docker",         "run",                    "--detach",     "--log-driver", "json-file", "--log-opt",  "max-size=1m", "--log-opt", "max-file=1", "--workdir",          "/",             "--name", probe_name,         "--network", network,    "--read-only",  "--cap-drop",  "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "64",           "--memory",  "128m",       "--cpus",      "1",         "--user",     "65532:65532",        "--entrypoint",  "curl",   probe_image,        "--disable", "--silent", "--show-error", "--fail",      "--noproxy",
        "*",              "--proto",                "=http",        "--max-redirs", "0",         "--max-time", "1",           "--retry",   timeout,      "--retry-all-errors", "--retry-delay", "1",      "--retry-max-time", timeout,     "--output", "/dev/null",    "--write-out", "%{http_code}",
        url,
    }, 30);
    if (try waitForExit(allocator, io, probe_name, options.timeout_seconds + 2) != 0) return error.SmokeFailed;
    const response = process(allocator, io, &.{ "docker", "logs", "--tail", "20", probe_name }, 10) catch return error.SmokeFailed;
    defer allocator.free(response.stdout);
    defer allocator.free(response.stderr);
    const status = std.fmt.parseInt(u16, response.stdout, 10) catch 0;
    if (!succeeded(response) or status < 200 or status >= 300) return error.SmokeFailed;
    return .{ .mode = .http, .passed = true, .http_status = status };
}

fn waitForExit(allocator: std.mem.Allocator, io: Io, name: []const u8, seconds: u16) !u32 {
    const start = Io.Clock.awake.now(io);
    while (Io.Clock.awake.now(io).toNanoseconds() - start.toNanoseconds() < @as(i96, seconds) * std.time.ns_per_s) {
        const state = process(allocator, io, &.{ "docker", "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", name }, 10) catch return error.SmokeFailed;
        defer allocator.free(state.stdout);
        defer allocator.free(state.stderr);
        if (!succeeded(state)) return error.SmokeFailed;
        const text = std.mem.trim(u8, state.stdout, " \r\n\t");
        if (std.mem.startsWith(u8, text, "false ")) return std.fmt.parseInt(u32, text[6..], 10) catch error.SmokeFailed;
        if (!std.mem.startsWith(u8, text, "true ")) return error.SmokeFailed;
        try Io.sleep(io, .fromMilliseconds(100), .awake);
    }
    return error.SmokeFailed;
}

fn process(allocator: std.mem.Allocator, io: Io, argv: []const []const u8, seconds: u16) !std.process.RunResult {
    return std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } },
    });
}

fn succeeded(result: std.process.RunResult) bool {
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn checked(allocator: std.mem.Allocator, io: Io, argv: []const []const u8, seconds: u16) !void {
    const result = process(allocator, io, argv, seconds) catch return error.SmokeFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (!succeeded(result)) {
        std.debug.print("smoke command failed: {s}\n", .{result.stderr});
        return error.SmokeFailed;
    }
}

fn cleanup(allocator: std.mem.Allocator, io: Io, argv: []const []const u8) void {
    const result = process(allocator, io, argv, 30) catch return;
    allocator.free(result.stdout);
    allocator.free(result.stderr);
}

test "smoke configuration forbids conflicting modes and HTTP injection" {
    try validate(.{ .command = &.{ "/app/application", "--self-test" } });
    try validate(.{ .http_path = "/health?ready=true" });
    try std.testing.expectError(error.InvalidSmokeOptions, validate(.{ .http_path = "/health\r\nHost: attacker" }));
    try std.testing.expectError(error.InvalidSmokeOptions, validate(.{ .http_path = "/health", .command = &.{"true"} }));
    try std.testing.expectError(error.InvalidSmokeOptions, validate(.{ .timeout_seconds = 0 }));
}
