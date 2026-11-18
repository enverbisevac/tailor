const std = @import("std");
const Io = std.Io;
const artifact = @import("artifact.zig");
const dockerfile = @import("dockerfile.zig");
const security = @import("security.zig");
const snapshot = @import("snapshot.zig");
const lockfile = @import("lockfile.zig");

pub const Options = struct {
    input: []const u8,
    tag: []const u8,
    base: ?[]const u8 = null,
    builder_base: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    extra_files: []const dockerfile.ExtraFile = &.{},
    native_files: []const @import("dependencies.zig").File = &.{},
    native_root: ?[]const u8 = null,
    scanner: ?security.Scanner = null,
    environment: ?*const std.process.Environ.Map = null,
    platform: ?[]const u8 = null,
    locked: bool = false,
    lock_path: []const u8 = "tailor.lock",
    require_platform: bool = false,
    source: ?[]const u8 = null,
    commands: []const []const u8 = &.{},
    libraries: []const []const u8 = &.{},
    native_resolution: bool = false,
    sysroot: ?[]const u8 = null,
    smoke: lockfile.Smoke = .{},
    attest: bool = false,
};

pub const BuildError = error{
    DockerFailed,
    InvalidExtraFile,
    InvalidTag,
    TargetExists,
} || artifact.InspectError || dockerfile.GenerateError || security.GateError ||
    std.mem.Allocator.Error || Io.Dir.WriteFileError || Io.RandomSecureError || std.process.RunError;

/// Build under an unpredictable temporary tag, scan the complete image, and
/// only then create the requested tag. A vulnerable candidate is never promoted.
pub const Prepared = struct {
    context: snapshot.Snapshot,
    inspection: artifact.Inspection,
    contents: []u8,
    plan: []u8,
    platform: ?[]const u8,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator, io: Io) void {
        allocator.free(self.contents);
        allocator.free(self.plan);
        self.context.deinit(io);
    }
};

/// Lock generation and builds hash the same staged bytes and generated plan.
pub fn prepare(allocator: std.mem.Allocator, io: Io, options: Options) !Prepared {
    try @import("smoke.zig").validate(options.smoke);
    var context = try snapshot.Snapshot.init(allocator, io);
    errdefer context.deinit(io);
    const ignored = try snapshot.normalizePath(allocator, options.lock_path);
    defer allocator.free(ignored);
    context.ignored_path = ignored;
    defer context.ignored_path = null;
    try context.add(io, options.input);
    for (options.extra_files) |file| try context.add(io, file.source);
    if (options.source) |source| try context.add(io, source);
    const input_count = context.entries.items.len;
    for (options.native_files) |file| {
        try context.add(io, file.source);
        var matched = false;
        for (context.entries.items) |entry| {
            if (std.mem.eql(u8, entry.path, file.source) and std.mem.eql(u8, &entry.sha256, &file.sha256)) matched = true;
        }
        if (!matched) return error.SourceChanged;
        if (std.mem.eql(u8, file.destination, "/var/lib/dpkg/status")) {
            const metadata = try context.dir.readFileAlloc(io, file.source, allocator, .limited(32 * 1024 * 1024));
            defer allocator.free(metadata);
            try context.dir.createDirPath(io, "var/lib/dpkg");
            try context.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = metadata, .flags = .{ .exclusive = true } });
        }
    }
    const snapshot_input = try context.joined(options.input);
    defer allocator.free(snapshot_input);
    const inspection = try artifact.inspect(io, snapshot_input);
    for (options.extra_files) |file| artifact.validateRegularFile(io, file.source) catch return error.InvalidExtraFile;

    const contents = try dockerfile.generate(allocator, inspection, .{
        .input = options.input,
        .base = options.base,
        .builder_base = options.builder_base,
        .entrypoint = options.entrypoint,
        .extra_files = options.extra_files,
        .native_files = options.native_files,
        .native_root = options.native_root,
    });
    errdefer allocator.free(contents);
    var platform = try lockfile.target(inspection.architecture, options.platform, options.locked or options.require_platform);
    // Resolve against the staged artifact/source as well, so a concurrent
    // edit cannot pair newly hashed inputs with an older dependency closure.
    if (options.sysroot) |root| {
        var resolved = try @import("dependencies.zig").Resolver.init(allocator, io, root);
        defer resolved.deinit(io);
        if (inspection.kind == .static_elf or inspection.kind == .dynamic_elf) try resolved.application(io, snapshot_input);
        for (options.commands) |command| try resolved.command(io, command);
        if (options.source) |source| {
            const staged_source = try context.joined(source);
            defer allocator.free(staged_source);
            try resolved.discover(io, staged_source, options.commands.len > 0);
        } else if (inspection.kind == .node_project or inspection.kind == .python_project) try resolved.discover(io, snapshot_input, options.commands.len > 0);
        for (options.libraries) |library| try resolved.library(io, library);
        try resolved.packageInventory(io);
        std.mem.sort(@import("dependencies.zig").File, resolved.files.items, {}, struct {
            fn less(_: void, x: @import("dependencies.zig").File, y: @import("dependencies.zig").File) bool {
                return std.mem.lessThan(u8, x.destination, y.destination);
            }
        }.less);
        if (resolved.files.items.len != options.native_files.len) return error.SourceChanged;
        for (resolved.files.items, options.native_files) |actual, expected| {
            if (!std.mem.eql(u8, actual.destination, expected.destination) or !std.mem.eql(u8, &actual.sha256, &expected.sha256) or
                !optionalEqual(actual.package, expected.package) or !optionalEqual(actual.package_version, expected.package_version)) return error.SourceChanged;
        }
        if (resolved.machine) |machine| {
            const arch: artifact.Architecture = switch (machine) {
                62 => .amd64,
                183 => .arm64,
                40 => .arm,
                243 => .riscv64,
                3 => .x86,
                else => return error.PlatformMismatch,
            };
            const native_platform = (try lockfile.target(arch, null, false)).?;
            if (platform) |selected| {
                if (!std.mem.eql(u8, selected, native_platform)) return error.PlatformMismatch;
            } else platform = native_platform;
        }
    }
    const plan = try lockfile.render(allocator, @import("build_options").version, .{
        .input = options.input,
        .platform = platform orelse "unspecified",
        .base = options.base,
        .builder_base = options.builder_base,
        .entrypoint = options.entrypoint,
        .source = options.source,
        .commands = options.commands,
        .libraries = options.libraries,
        .extra_files = options.extra_files,
        .native_resolution = options.native_resolution,
        .smoke = options.smoke,
        .attest = options.attest,
    }, context.entries.items[0..input_count], options.native_files, contents);
    errdefer allocator.free(plan);
    if (options.locked) {
        try artifact.validateRegularFile(io, options.lock_path);
        const saved = try Io.Dir.cwd().readFileAlloc(io, options.lock_path, allocator, .limited(32 * 1024 * 1024));
        defer allocator.free(saved);
        try lockfile.verify(allocator, saved, plan);
    }
    return .{ .context = context, .inspection = inspection, .contents = contents, .plan = plan, .platform = platform };
}

pub fn build(allocator: std.mem.Allocator, io: Io, options: Options) !void {
    const started_at = Io.Clock.real.now(io).toSeconds();
    try validateTag(options.tag);
    var prepared = try prepare(allocator, io, options);
    defer prepared.deinit(allocator, io);
    const context = &prepared.context;
    const inspection = prepared.inspection;
    const contents = prepared.contents;
    const platform = prepared.platform;
    const scanner = options.scanner orelse security.detectScanner(allocator, io) orelse return error.ScannerMissing;
    std.debug.print("using {s}; all requested gates must pass before promotion\n", .{scanner.command()});
    try ensureDockerReady(allocator, io);
    if (try imageExists(allocator, io, options.tag)) return error.TargetExists;
    try context.writeManifest(io);

    // Scan declared dependencies before a package installation step can run.
    try security.scanSource(allocator, io, scanner, context.path, options.environment);

    switch (inspection.kind) {
        .static_elf => {},
        .dynamic_elf, .jar => if (options.base) |base| try preflightBase(allocator, io, scanner, base, platform, options.environment),
        .node_project, .python_project => {
            try preflightBase(allocator, io, scanner, options.base.?, platform, options.environment);
            if (!std.mem.eql(u8, options.base.?, options.builder_base.?))
                try preflightBase(allocator, io, scanner, options.builder_base.?, platform, options.environment);
        },
    }

    try @import("runtime.zig").validateForPlatform(allocator, io, inspection.kind, options.base, options.builder_base, platform);

    var random_bytes: [8]u8 = undefined;
    try io.randomSecure(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const dockerfile_path = try context.joined("Dockerfile");
    defer allocator.free(dockerfile_path);
    const candidate = try std.fmt.allocPrint(allocator, "tailor.local/candidate-{x:0>16}:pending", .{nonce});
    defer allocator.free(candidate);
    const iid_path = try std.fmt.allocPrint(allocator, ".tailor-{x:0>16}.iid", .{nonce});
    defer allocator.free(iid_path);
    defer Io.Dir.cwd().deleteFile(io, iid_path) catch {};

    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = dockerfile_path,
        .data = contents,
        .flags = .{ .exclusive = true },
    });
    defer Io.Dir.cwd().deleteFile(io, dockerfile_path) catch {};
    try context.dir.writeFile(io, .{
        .sub_path = ".dockerignore",
        .data = "Dockerfile\ntailor-inputs.json\n.dockerignore\nvar/lib/dpkg/status\n",
        .flags = .{ .exclusive = true },
    });

    if (platform) |value| {
        try runDocker(allocator, io, &.{
            "docker",     "build", "--iidfile",  iid_path, "--file", dockerfile_path, "--tag", candidate,
            "--platform", value,   context.path,
        });
    } else {
        try runDocker(allocator, io, &.{
            "docker", "build", "--iidfile", iid_path, "--file", dockerfile_path, "--tag", candidate, context.path,
        });
    }

    var candidate_exists = true;
    defer if (candidate_exists) removeCandidate(allocator, io, candidate);

    const iid_contents = Io.Dir.cwd().readFileAlloc(io, iid_path, allocator, .limited(128)) catch
        return error.DockerFailed;
    defer allocator.free(iid_contents);
    const image_id = std.mem.trim(u8, iid_contents, " \r\n\t");
    if (!validImageId(image_id)) return error.DockerFailed;

    // Recheck the assembled runtime after native libraries have been grafted
    // in. Python probes use isolated mode so project modules cannot shadow
    // the standard library or execute sitecustomize hooks during the probe.
    try @import("runtime.zig").validateForPlatform(allocator, io, inspection.kind, image_id, options.builder_base, platform);
    try security.scanImage(allocator, io, scanner, image_id, options.environment);
    const smoke_result = try @import("smoke.zig").run(allocator, io, image_id, options.smoke, platform);
    if (options.attest) {
        const evidence = @import("attestation.zig").exportImage(allocator, io, image_id, prepared.plan, smoke_result, scanner, options.environment, started_at) catch |err| {
            std.debug.print("attestation export failed: {s}\n", .{@errorName(err)});
            return error.AttestationFailed;
        };
        defer allocator.free(evidence);
        std.debug.print("OCI image and attached SBOM/provenance: {s}\n", .{evidence});
    }
    if (try imageExists(allocator, io, options.tag)) return error.TargetExists;
    try runDocker(allocator, io, &.{ "docker", "tag", image_id, options.tag });
    removeCandidate(allocator, io, candidate);
    candidate_exists = false;
}

fn validImageId(value: []const u8) bool {
    if (!std.mem.startsWith(u8, value, "sha256:") or value.len != 71) return false;
    for (value[7..]) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    return true;
}

fn optionalEqual(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |left| return if (b) |right| std.mem.eql(u8, left, right) else false;
    return b == null;
}

fn preflightBase(
    allocator: std.mem.Allocator,
    io: Io,
    scanner: security.Scanner,
    image: []const u8,
    platform: ?[]const u8,
    environment: ?*const std.process.Environ.Map,
) BuildError!void {
    if (platform) |value| {
        try runDocker(allocator, io, &.{ "docker", "pull", "--platform", value, image });
    } else {
        try runDocker(allocator, io, &.{ "docker", "pull", image });
    }
    try security.scanImage(allocator, io, scanner, image, environment);
}

fn ensureDockerReady(allocator: std.mem.Allocator, io: Io) BuildError!void {
    try runDocker(allocator, io, &.{ "docker", "version", "--format", "{{.Server.Version}}" });
}

fn imageExists(allocator: std.mem.Allocator, io: Io, tag: []const u8) BuildError!bool {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "docker", "image", "inspect", tag },
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => error.DockerFailed,
    };
}

fn runDocker(allocator: std.mem.Allocator, io: Io, argv: []const []const u8) BuildError!void {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(128 * 1024 * 1024),
        .stderr_limit = .limited(128 * 1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.stdout.len != 0) std.debug.print("{s}", .{result.stdout});
    if (result.stderr.len != 0) std.debug.print("{s}", .{result.stderr});
    switch (result.term) {
        .exited => |code| if (code != 0) return error.DockerFailed,
        else => return error.DockerFailed,
    }
}

fn removeCandidate(allocator: std.mem.Allocator, io: Io, candidate: []const u8) void {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "docker", "image", "rm", candidate },
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
    }) catch {
        std.debug.print("tailor: warning: could not remove temporary image {s}\n", .{candidate});
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0)
            std.debug.print("tailor: warning: could not remove temporary image {s}\n", .{candidate}),
        else => std.debug.print("tailor: warning: could not remove temporary image {s}\n", .{candidate}),
    }
}

fn platformFor(architecture: artifact.Architecture) ?[]const u8 {
    return switch (architecture) {
        .amd64 => "linux/amd64",
        .arm64 => "linux/arm64",
        .arm => "linux/arm/v7",
        .riscv64 => "linux/riscv64",
        .x86 => "linux/386",
        .unknown => null,
    };
}

fn validateTag(tag: []const u8) error{InvalidTag}!void {
    if (tag.len == 0 or tag.len > 255 or tag[0] == '-') return error.InvalidTag;
    for (tag) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '-' or byte == '/' or byte == ':'))
            return error.InvalidTag;
    }
}

test "container tags reject shell and control syntax" {
    try validateTag("registry.example/team/server:candidate");
    try std.testing.expectError(error.InvalidTag, validateTag("server;whoami"));
    try std.testing.expectError(error.InvalidTag, validateTag("server\nFROM evil"));
}

test "promotion accepts only a complete immutable image ID" {
    try std.testing.expect(validImageId("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try std.testing.expect(!validImageId("candidate:latest"));
    try std.testing.expect(!validImageId("sha256:abcd"));
    try std.testing.expect(!validImageId("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}
