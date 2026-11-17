const std = @import("std");
const Io = std.Io;

pub const Scanner = enum {
    osv,
    grype,
    trivy,

    pub fn command(self: Scanner) []const u8 {
        return switch (self) {
            .osv => "osv-scanner",
            .grype => "grype",
            .trivy => "trivy",
        };
    }
};

pub const GateError = error{
    ScanFailed,
    ScannerCrashed,
    InvalidScanReport,
    ScanCoverageMissing,
    CatalogFailed,
    StaleDatabase,
} || std.process.RunError || Io.Dir.WriteFileError || Io.RandomSecureError;

pub fn detectScanner(allocator: std.mem.Allocator, io: Io) ?Scanner {
    const candidates = [_]Scanner{ .osv, .grype, .trivy };
    for (candidates) |scanner| {
        const result = std.process.run(allocator, io, .{
            .argv = &.{ scanner.command(), "--version" },
            .stdout_limit = .limited(1024 * 1024),
            .stderr_limit = .limited(1024 * 1024),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } },
        }) catch continue;
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (termSucceeded(result.term)) return scanner;
    }
    return null;
}

pub fn scanSource(
    allocator: std.mem.Allocator,
    io: Io,
    scanner: Scanner,
    path: []const u8,
    environment: ?*const std.process.Environ.Map,
) GateError!void {
    const policy = try EmptyPolicy.create(allocator, io, scanner);
    defer policy.deinit(allocator, io);
    switch (scanner) {
        .osv => {
            const config_arg = try std.fmt.allocPrint(allocator, "--config={s}", .{policy.path});
            defer allocator.free(config_arg);
            try runGate(allocator, io, &.{ "osv-scanner", "scan", "source", "--format=json", "--all-packages", "--recursive", path, config_arg }, environment, null);
        },
        .grype => {
            const stat = Io.Dir.cwd().statFile(io, path, .{}) catch null;
            const scheme: []const u8 = if (stat) |value| switch (value.kind) {
                .file => "file:",
                else => "dir:",
            } else "dir:";
            const target = try std.fmt.allocPrint(allocator, "{s}{s}", .{ scheme, path });
            defer allocator.free(target);
            try runGate(allocator, io, &.{ "grype", "--config", policy.path, target, "--output", "json", "--fail-on", "negligible" }, environment, null);
        },
        .trivy => try runGate(allocator, io, &.{
            "trivy",           "--config", policy.path,  "filesystem",                       "--ignorefile", policy.path,
            "--exit-code",     "1",        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--format",     "json",
            "--list-all-pkgs", path,
        }, environment, null),
    }
}

pub fn scanImage(
    allocator: std.mem.Allocator,
    io: Io,
    scanner: Scanner,
    image: []const u8,
    environment: ?*const std.process.Environ.Map,
) GateError!void {
    const policy = try EmptyPolicy.create(allocator, io, scanner);
    defer policy.deinit(allocator, io);
    switch (scanner) {
        .osv => {
            const config_arg = try std.fmt.allocPrint(allocator, "--config={s}", .{policy.path});
            defer allocator.free(config_arg);
            try runGate(allocator, io, &.{ "osv-scanner", "scan", "image", "--format=json", "--all-packages", image, config_arg }, environment, null);
        },
        .grype => {
            const target = try std.fmt.allocPrint(allocator, "docker:{s}", .{image});
            defer allocator.free(target);
            const inventory = try catalogImage(allocator, io, target, environment);
            try runGate(allocator, io, &.{ "grype", "--config", policy.path, target, "--output", "json", "--fail-on", "negligible" }, environment, inventory);
        },
        .trivy => try runGate(allocator, io, &.{
            "trivy",           "--config", policy.path,  "image",                            "--ignorefile", policy.path,
            "--exit-code",     "1",        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--format",     "json",
            "--list-all-pkgs", image,
        }, environment, null),
    }
}

const EmptyPolicy = struct {
    path: []u8,

    fn create(allocator: std.mem.Allocator, io: Io, scanner: Scanner) GateError!EmptyPolicy {
        var random_bytes: [8]u8 = undefined;
        try io.randomSecure(&random_bytes);
        const nonce = std.mem.readInt(u64, &random_bytes, .little);
        const extension: []const u8 = if (scanner == .osv) ".toml" else ".yaml";
        const path = try std.fmt.allocPrint(allocator, ".tailor-scan-policy-{x:0>16}{s}", .{ nonce, extension });
        errdefer allocator.free(path);
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = path,
            .data = if (scanner == .grype) "db:\n  auto-update: true\n  validate-age: true\n  max-allowed-built-age: 120h\n  validate-by-hash-on-start: true\n" else "",
            .flags = .{ .exclusive = true },
        });
        return .{ .path = path };
    }

    fn deinit(self: EmptyPolicy, allocator: std.mem.Allocator, io: Io) void {
        Io.Dir.cwd().deleteFile(io, self.path) catch
            std.debug.print("tailor: warning: could not remove temporary scanner policy {s}\n", .{self.path});
        allocator.free(self.path);
    }
};

fn runGate(allocator: std.mem.Allocator, io: Io, argv: []const []const u8, environment: ?*const std.process.Environ.Map, inventory: ?usize) GateError!void {
    var safe_environment = try scannerEnvironment(allocator, environment);
    defer safe_environment.deinit();
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .environ_map = &safe_environment,
        .stdout_limit = .limited(64 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.stderr.len != 0) std.debug.print("{s}", .{result.stderr});
    // Keep raw evidence even when parsing fails or a scanner returns an error.
    var nonce: [16]u8 = undefined;
    try io.randomSecure(&nonce);
    Io.Dir.cwd().createDir(io, ".tailor-reports", .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.InvalidScanReport,
    };
    const report_dir = Io.Dir.cwd().openDir(io, ".tailor-reports", .{ .follow_symlinks = false }) catch return error.InvalidScanReport;
    defer report_dir.close(io);
    const report_name = try std.fmt.allocPrint(allocator, "{s}-{s}.json", .{ argv[0], std.fmt.bytesToHex(nonce, .lower) });
    defer allocator.free(report_name);
    try report_dir.writeFile(io, .{ .sub_path = report_name, .data = result.stdout, .flags = .{ .exclusive = true } });
    std.debug.print("scan evidence: .tailor-reports/{s}\n", .{report_name});
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch return error.InvalidScanReport;
    defer parsed.deinit();
    var summary = @import("scan_report.zig").summarize(argv[0], parsed.value) catch return error.InvalidScanReport;
    if (std.mem.eql(u8, argv[0], "grype")) {
        @import("scan_report.zig").validateGrypeFreshness(parsed.value, Io.Clock.real.now(io).toSeconds()) catch |err| switch (err) {
            error.StaleDatabase => return error.StaleDatabase,
            else => return error.InvalidScanReport,
        };
    }
    if (inventory) |count| {
        summary.packages = count;
        summary.inventory_complete = true;
    }
    const summary_name = try std.fmt.allocPrint(allocator, "{s}.summary.json", .{report_name});
    defer allocator.free(summary_name);
    const normalized = try std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = 1,
        .scanner = argv[0],
        .arguments = argv,
        .scanned_at_unix = Io.Clock.real.now(io).toSeconds(),
        .raw_report = report_name,
        .summary = summary,
        .process_succeeded = termSucceeded(result.term),
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(normalized);
    try report_dir.writeFile(io, .{ .sub_path = summary_name, .data = normalized, .flags = .{ .exclusive = true } });
    std.debug.print("scan: {d} packages, {d} vulnerabilities, {d} suppressed\n", .{ summary.packages, summary.vulnerabilities, summary.suppressed });
    if (summary.vulnerabilities != 0 or summary.suppressed != 0) return error.ScanFailed;
    // An empty inventory cannot establish that an image is clean. Empty source
    // projects are allowed; their installed runtime is scanned separately.
    var is_image = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "image") or std.mem.startsWith(u8, arg, "docker:")) is_image = true;
    }
    if (is_image and (summary.packages == 0 or !summary.inventory_complete)) return error.ScanCoverageMissing;
    switch (result.term) {
        .exited => |code| if (code != 0) return error.ScanFailed,
        else => return error.ScannerCrashed,
    }
}

fn catalogImage(allocator: std.mem.Allocator, io: Io, target: []const u8, environment: ?*const std.process.Environ.Map) GateError!usize {
    const policy = try EmptyPolicy.create(allocator, io, .trivy);
    defer policy.deinit(allocator, io);
    var safe = try scannerEnvironment(allocator, environment);
    defer safe.deinit();
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "syft", "scan", target, "--config", policy.path, "--output", "syft-json" },
        .environ_map = &safe,
        .stdout_limit = .limited(64 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } },
    }) catch return error.CatalogFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (!termSucceeded(result.term)) {
        std.debug.print("Grype image scans require Syft for complete package coverage: {s}\n", .{result.stderr});
        return error.CatalogFailed;
    }
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch return error.CatalogFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return error.CatalogFailed;
    const artifacts = parsed.value.object.get("artifacts") orelse return error.CatalogFailed;
    if (artifacts != .array) return error.CatalogFailed;
    var nonce: [16]u8 = undefined;
    try io.randomSecure(&nonce);
    Io.Dir.cwd().createDir(io, ".tailor-reports", .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.CatalogFailed,
    };
    const directory = Io.Dir.cwd().openDir(io, ".tailor-reports", .{ .follow_symlinks = false }) catch return error.CatalogFailed;
    defer directory.close(io);
    const filename = try std.fmt.allocPrint(allocator, "syft-{s}.json", .{std.fmt.bytesToHex(nonce, .lower)});
    defer allocator.free(filename);
    try directory.writeFile(io, .{ .sub_path = filename, .data = result.stdout, .flags = .{ .exclusive = true } });
    std.debug.print("package inventory: .tailor-reports/{s}\n", .{filename});
    return artifacts.array.items.len;
}

/// Preserve transport, cache-location, and executable lookup settings only.
/// Scanner filtering and executable-injection variables never reach children.
pub fn scannerEnvironment(allocator: std.mem.Allocator, parent: ?*const std.process.Environ.Map) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(allocator);
    errdefer result.deinit();
    if (parent) |source| {
        for ([_][]const u8{
            "PATH",           "HOME",            "USERPROFILE", "SYSTEMROOT",     "TEMP",          "TMP",               "TMPDIR",
            "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
            "HTTP_PROXY",     "HTTPS_PROXY",     "NO_PROXY",    "http_proxy",     "https_proxy",   "no_proxy",          "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }) |key| {
            if (source.get(key)) |value| try result.put(key, value);
        }
    }
    return result;
}

fn termSucceeded(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "scanner command names are stable" {
    try std.testing.expectEqualStrings("osv-scanner", Scanner.osv.command());
    try std.testing.expectEqualStrings("grype", Scanner.grype.command());
    try std.testing.expectEqualStrings("trivy", Scanner.trivy.command());
}

test "scanner environment preserves transport but removes filtering and injection settings" {
    const allocator = std.testing.allocator;
    var parent = std.process.Environ.Map.init(allocator);
    defer parent.deinit();
    try parent.put("PATH", "/usr/bin");
    try parent.put("HTTPS_PROXY", "http://proxy.example:8080");
    try parent.put("GRYPE_ONLY_FIXED", "true");
    try parent.put("TRIVY_IGNORE_UNFIXED", "true");
    try parent.put("TRIVY_SKIP_FILES", "**");
    try parent.put("LD_PRELOAD", "/tmp/inject.so");
    var safe = try scannerEnvironment(allocator, &parent);
    defer safe.deinit();
    try std.testing.expectEqualStrings("/usr/bin", safe.get("PATH").?);
    try std.testing.expectEqualStrings("http://proxy.example:8080", safe.get("HTTPS_PROXY").?);
    try std.testing.expectEqual(@as(usize, 2), safe.count());
}
