const std = @import("std");
const Io = std.Io;
const tailor = @import("tailor");

const usage =
    \\Tailor creates minimal, fail-closed container build plans from application artifacts.
    \\
    \\Usage:
    \\  tailor --version
    \\  tailor inspect <input>
    \\  tailor deps <input> --sysroot <linux-rootfs> [--exec <command>] [--library <soname>]
    \\  tailor generate <input> [--output <file>] [runtime options]
    \\  tailor build <input> --tag <image:tag> [runtime options] [--scanner <osv|grype|trivy>]
    \\  tailor scan <source|image> <target> [--scanner <osv|grype|trivy>]
    \\  tailor check-report <osv|grype|trivy> <report.json>
    \\  tailor verify-runtime <python|node|java> --base <digest> [--builder-base <digest>]
    \\
    \\Runtime options:
    \\  --base <image@sha256:digest>
    \\  --builder-base <image@sha256:digest>     Required for Node.js and Python
    \\  --entrypoint <module-or-script>          Required for Node.js and Python
    \\  --include <source-file> <container-path> May be repeated
    \\  --sysroot <linux-rootfs>                 Resolve ELF dependencies inside this directory
    \\  --exec <command>                        Include an external command from the sysroot
    \\  --library <soname>                      Include a runtime-loaded library from the sysroot
    \\  --source <directory>                    Discover direct process calls in source files
    \\
    \\Notes:
    \\  Paths must be relative to the Docker build context and may not contain '..'.
    \\  Existing regular output files are updated; identical output is left untouched.
    \\  Dynamic ELF requires a pinned runtime base or a resolved --sysroot closure.
    \\  Java, Node.js, and Python require a digest-pinned runtime base.
    \\  Node.js projects require package-lock.json v2/v3 with integrity metadata.
    \\  Python requirements must use exact versions and sha256 hashes.
    \\
;

pub fn main(init: std.process.Init) !void {
    run(init) catch |err| switch (err) {
        error.TailorFailed => std.process.exit(1),
        else => return err,
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    if (args.len < 2 or isHelp(args[1])) {
        try stdout.writeAll(usage);
        return;
    }

    if (std.mem.eql(u8, args[1], "--version")) {
        if (args.len != 2) return fail("--version accepts no arguments", .{});
        try stdout.print("tailor {s}\n", .{tailor.version});
        return;
    }

    if (std.mem.eql(u8, args[1], "inspect")) {
        if (args.len != 3) return fail("inspect expects exactly one input path", .{});
        const result = tailor.artifact.inspect(init.io, args[2]) catch |err| return explainInspectionError(err);
        try printInspection(stdout, args[2], result);
        return;
    }

    if (std.mem.eql(u8, args[1], "generate")) {
        try generate(init.io, allocator, stdout, args);
        return;
    }

    if (std.mem.eql(u8, args[1], "deps")) {
        if (args.len < 5) return fail("deps expects <input> --sysroot <linux-rootfs>", .{});
        var native: NativeOptions = .{};
        defer native.deinit(allocator);
        var index: usize = 3;
        while (index < args.len) {
            const option = args[index];
            index += 1;
            if (!try native.consume(allocator, option, args, &index)) return fail("unknown dependency option: {s}", .{option});
        }
        var resolved = try native.resolve(allocator, init.io, args[2]);
        defer if (resolved) |*resolver| resolver.deinit(init.io);
        if (resolved == null) return fail("deps requires --sysroot", .{});
        const json = try std.json.Stringify.valueAlloc(allocator, .{ .schema_version = 1, .machine = resolved.?.machine, .files = resolved.?.files.items }, .{ .whitespace = .indent_2 });
        try stdout.print("{s}\n", .{json});
        return;
    }

    if (std.mem.eql(u8, args[1], "build")) {
        try build(init.io, allocator, stdout, args, init.environ_map);
        return;
    }

    if (std.mem.eql(u8, args[1], "scan")) {
        try scan(init.io, allocator, args, init.environ_map);
        return;
    }

    if (std.mem.eql(u8, args[1], "check-report")) {
        if (args.len != 4) return fail("check-report expects <scanner> <report.json>", .{});
        const scanner = parseScanner(args[2]) orelse return fail("unknown scanner", .{});
        const bytes = try Io.Dir.cwd().readFileAlloc(init.io, args[3], allocator, .limited(64 * 1024 * 1024));
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();
        const summary = try tailor.scan_report.summarize(scanner.command(), parsed.value);
        try stdout.print("packages: {d}, vulnerabilities: {d}, suppressed: {d}\n", .{ summary.packages, summary.vulnerabilities, summary.suppressed });
        if (summary.vulnerabilities > 0 or summary.suppressed > 0) return fail("report contains blocking findings", .{});
        if (summary.packages == 0 or !summary.inventory_complete) return fail("report has no complete package inventory; coverage cannot be established", .{});
        if (scanner == .grype) try tailor.scan_report.validateGrypeFreshness(parsed.value, Io.Clock.real.now(init.io).toSeconds());
        return;
    }

    if (std.mem.eql(u8, args[1], "verify-runtime")) {
        if (args.len < 5) return fail("verify-runtime expects <language> --base <digest> [--builder-base <digest>]", .{});
        const kind: tailor.artifact.Kind = if (std.mem.eql(u8, args[2], "python")) .python_project else if (std.mem.eql(u8, args[2], "node")) .node_project else if (std.mem.eql(u8, args[2], "java")) .jar else return fail("runtime must be python, node, or java", .{});
        var base: ?[]const u8 = null;
        var builder: ?[]const u8 = null;
        var index: usize = 3;
        while (index < args.len) : (index += 2) {
            if (index + 1 >= args.len) return fail("missing runtime image", .{});
            if (std.mem.eql(u8, args[index], "--base")) base = args[index + 1] else if (std.mem.eql(u8, args[index], "--builder-base")) builder = args[index + 1] else return fail("unknown runtime option", .{});
        }
        _ = try tailor.dockerfile.requirePinnedBase(base);
        if (kind != .jar) _ = try tailor.dockerfile.requirePinnedBase(builder);
        try tailor.runtime.validate(allocator, init.io, kind, base, builder);
        try stdout.writeAll("runtime compatibility verified\n");
        return;
    }

    return fail("unknown command: {s}\n\n{s}", .{ args[1], usage });
}

fn build(
    io: Io,
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    args: []const []const u8,
    environment: *const std.process.Environ.Map,
) !void {
    if (args.len < 5) return fail("build expects <input> --tag <image:tag>", .{});
    const input = args[2];
    var tag: ?[]const u8 = null;
    var base: ?[]const u8 = null;
    var builder_base: ?[]const u8 = null;
    var entrypoint: ?[]const u8 = null;
    var scanner: ?tailor.security.Scanner = null;
    var native: NativeOptions = .{};
    defer native.deinit(allocator);
    var extra_files: std.ArrayList(tailor.dockerfile.ExtraFile) = .empty;
    defer extra_files.deinit(allocator);

    var index: usize = 3;
    while (index < args.len) {
        const option = args[index];
        index += 1;
        if (try native.consume(allocator, option, args, &index)) continue;
        if (std.mem.eql(u8, option, "--include")) {
            if (index + 1 >= args.len) return fail("--include expects <source-file> <container-path>", .{});
            try extra_files.append(allocator, .{ .source = args[index], .destination = args[index + 1] });
            index += 2;
            continue;
        }
        if (index >= args.len) return fail("missing value for {s}", .{option});
        const value = args[index];
        index += 1;
        if (std.mem.eql(u8, option, "--tag")) {
            tag = value;
        } else if (std.mem.eql(u8, option, "--base")) {
            base = value;
        } else if (std.mem.eql(u8, option, "--builder-base")) {
            builder_base = value;
        } else if (std.mem.eql(u8, option, "--entrypoint")) {
            entrypoint = value;
        } else if (std.mem.eql(u8, option, "--scanner")) {
            scanner = parseScanner(value) orelse return fail("scanner must be osv, grype, or trivy", .{});
        } else {
            return fail("unknown option: {s}", .{option});
        }
    }

    const requested_tag = tag orelse return fail("build requires --tag <image:tag>", .{});
    var resolved = try native.resolve(allocator, io, input);
    defer if (resolved) |*resolver| resolver.deinit(io);
    const selected_scanner = scanner orelse tailor.security.detectScanner(allocator, io) orelse
        return fail("no supported scanner found; install osv-scanner, grype, or trivy", .{});
    try stdout.print("using {s}; the requested tag will be created only after both scans pass\n", .{selected_scanner.command()});
    try stdout.flush();

    tailor.pipeline.build(allocator, io, .{
        .input = input,
        .tag = requested_tag,
        .base = base,
        .builder_base = builder_base,
        .entrypoint = entrypoint,
        .extra_files = extra_files.items,
        .scanner = selected_scanner,
        .environment = environment,
        .native_files = if (resolved) |resolver| resolver.files.items else &.{},
        .native_root = if (resolved) |resolver| resolver.tree else null,
    }) catch |err| switch (err) {
        error.TargetExists => return fail("target image already exists; choose a new tag", .{}),
        error.InvalidTag => return fail("invalid container image tag", .{}),
        error.InvalidExtraFile => return fail("included sources must be regular, non-symlink files inside the build context", .{}),
        error.InvalidExtraDestination => return fail("included destinations must be normalized absolute file paths and may not replace the application/runtime", .{}),
        error.DockerFailed => return fail("Docker command failed", .{}),
        error.ScanFailed => return fail("security gate failed; candidate image was not promoted", .{}),
        error.ScannerCrashed => return fail("security scanner terminated unexpectedly; candidate image was not promoted", .{}),
        error.CatalogFailed => return fail("Grype image scans require a working Syft installation and complete package inventory", .{}),
        error.InvalidScanReport => return fail("scanner returned an invalid or unsupported JSON report; inspect .tailor-reports", .{}),
        error.ScanCoverageMissing => return fail("no complete image package inventory was found; refusing to certify scan coverage", .{}),
        error.StaleDatabase => return fail("scanner database is invalid, older than 120 hours, or dated in the future", .{}),
        error.SnapshotLimitExceeded => return fail("build context exceeds the 128 MiB/file, 512 MiB/context, or file-count limit", .{}),
        error.UnsafeSnapshotEntry => return fail("build inputs contain a symlink or special file; provide regular files", .{}),
        error.SourceChanged => return fail("an input changed while staging; retry with stable build inputs", .{}),
        error.IncompatibleRuntime, error.InvalidRuntimeProbe, error.UnsupportedLibc => return fail("builder/runtime versions, architecture, native ABI, or glibc are incompatible or unverifiable", .{}),
        error.RuntimeBaseRequired => return fail("this artifact requires --base with an immutable image digest", .{}),
        error.BuilderBaseRequired => return fail("Node.js and Python require --builder-base with an immutable build image digest", .{}),
        error.InvalidBase => return fail("base must use the form registry/image@sha256:<64 lowercase hex characters>", .{}),
        error.ExecutableStack => return fail("refusing ELF with an executable stack", .{}),
        error.InvalidEntrypoint => return fail("invalid --entrypoint; use a Python module or a relative Node.js .js/.mjs/.cjs file", .{}),
        error.UnsupportedArtifact,
        error.NodeLockInvalid,
        error.PythonLockMissing,
        error.NotPortablePath,
        error.UnsupportedElfEndian,
        error.UnsupportedElfMachine,
        error.UnsupportedElfType,
        error.InvalidElf,
        error.EmptyFile,
        => |inspection_error| return explainInspectionError(inspection_error),
        else => |other| return other,
    };
    try stdout.print("created verified image {s}\n", .{requested_tag});
}

fn generate(
    io: Io,
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    args: []const []const u8,
) !void {
    if (args.len < 3) return fail("generate expects an input path", .{});
    const input = args[2];
    var output_path: []const u8 = "Dockerfile.tailor";
    var base: ?[]const u8 = null;
    var builder_base: ?[]const u8 = null;
    var entrypoint: ?[]const u8 = null;
    var native: NativeOptions = .{};
    defer native.deinit(allocator);
    var extra_files: std.ArrayList(tailor.dockerfile.ExtraFile) = .empty;
    defer extra_files.deinit(allocator);

    var index: usize = 3;
    while (index < args.len) {
        const option = args[index];
        index += 1;
        if (try native.consume(allocator, option, args, &index)) continue;
        if (std.mem.eql(u8, option, "--force")) {
            // Kept as a compatibility no-op. Generate now safely updates
            // existing regular files by default.
            continue;
        }
        if (std.mem.eql(u8, option, "--include")) {
            if (index + 1 >= args.len) return fail("--include expects <source-file> <container-path>", .{});
            try extra_files.append(allocator, .{ .source = args[index], .destination = args[index + 1] });
            index += 2;
            continue;
        }
        if (index >= args.len) return fail("missing value for {s}", .{option});
        const value = args[index];
        index += 1;
        if (std.mem.eql(u8, option, "--output")) {
            output_path = value;
        } else if (std.mem.eql(u8, option, "--base")) {
            base = value;
        } else if (std.mem.eql(u8, option, "--builder-base")) {
            builder_base = value;
        } else if (std.mem.eql(u8, option, "--entrypoint")) {
            entrypoint = value;
        } else {
            return fail("unknown option: {s}", .{option});
        }
    }

    tailor.artifact.validatePortablePath(output_path) catch
        return fail("output must be a relative path without '..'", .{});
    if (std.mem.eql(u8, output_path, input)) return fail("output may not replace the input artifact", .{});
    tailor.generated_file.rejectInputAlias(.cwd(), io, output_path, input) catch |err|
        return fail("unsafe output path: {s}", .{@errorName(err)});
    for (extra_files.items) |file| {
        if (std.mem.eql(u8, output_path, file.source)) return fail("output may not replace an included file", .{});
        tailor.generated_file.rejectInputAlias(.cwd(), io, output_path, file.source) catch |err|
            return fail("unsafe output path: {s}", .{@errorName(err)});
        tailor.artifact.validateRegularFile(io, file.source) catch
            return fail("included sources must be regular, non-symlink files inside the build context", .{});
    }
    const inspection = tailor.artifact.inspect(io, input) catch |err| return explainInspectionError(err);
    var resolved = try native.resolve(allocator, io, input);
    defer if (resolved) |*resolver| resolver.deinit(io);
    if (resolved) |resolver| for (resolver.files.items) |file| {
        try tailor.generated_file.rejectInputAlias(.cwd(), io, output_path, file.source);
    };
    const contents = tailor.dockerfile.generate(allocator, inspection, .{
        .input = input,
        .base = base,
        .builder_base = builder_base,
        .entrypoint = entrypoint,
        .extra_files = extra_files.items,
        .native_files = if (resolved) |resolver| resolver.files.items else &.{},
        .native_root = if (resolved) |resolver| resolver.tree else null,
    }) catch |err| switch (err) {
        error.RuntimeBaseRequired => return fail("{s} requires --base with an immutable image digest", .{inspection.kind.label()}),
        error.BuilderBaseRequired => return fail("Node.js and Python require --builder-base with an immutable build image digest", .{}),
        error.InvalidBase => return fail("base must use the form registry/image@sha256:<64 lowercase hex characters>", .{}),
        error.ExecutableStack => return fail("refusing ELF with an executable stack", .{}),
        error.InvalidEntrypoint => return fail("invalid --entrypoint; use a Python module or a relative Node.js .js/.mjs/.cjs file", .{}),
        error.InvalidExtraDestination => return fail("included destinations must be normalized absolute file paths and may not replace the application/runtime", .{}),
        else => |other| return other,
    };
    defer allocator.free(contents);

    const status = tailor.generated_file.write(Io.Dir.cwd(), allocator, io, output_path, contents) catch |err| switch (err) {
        error.UnsafeOutputPath => return fail("output must be a regular, non-symlink file with regular parent directories", .{}),
        error.ConcurrentModification => return fail("output changed concurrently; retry generation", .{}),
        else => |other| return other,
    };
    try stdout.print("{s} {s} for {s} ({s})\n", .{
        @tagName(status),
        output_path,
        inspection.kind.label(),
        inspection.architecture.label(),
    });
    if (inspection.kind == .static_elf and !inspection.is_pie) {
        try stdout.writeAll("warning: ELF is not position-independent; rebuild it as PIE when the toolchain supports that mode\n");
    }
    try stdout.writeAll("next: run a source scan, build the image, then scan the final image before publishing it\n");
}

fn scan(io: Io, allocator: std.mem.Allocator, args: []const []const u8, environment: *const std.process.Environ.Map) !void {
    if (args.len < 4) return fail("scan expects <source|image> <target>", .{});
    const scanner = if (args.len == 6 and std.mem.eql(u8, args[4], "--scanner"))
        parseScanner(args[5]) orelse return fail("scanner must be osv, grype, or trivy", .{})
    else if (args.len == 4)
        tailor.security.detectScanner(allocator, io) orelse return fail("no supported scanner found; install osv-scanner, grype, or trivy", .{})
    else
        return fail("invalid scan options", .{});

    if (std.mem.eql(u8, args[2], "source")) {
        tailor.security.scanSource(allocator, io, scanner, args[3], environment) catch |err| return explainScanError(err);
    } else if (std.mem.eql(u8, args[2], "image")) {
        tailor.security.scanImage(allocator, io, scanner, args[3], environment) catch |err| return explainScanError(err);
    } else {
        return fail("scan target type must be source or image", .{});
    }
}

fn printInspection(writer: *std.Io.Writer, path: []const u8, result: tailor.artifact.Inspection) !void {
    try writer.print("artifact: {s}\nkind: {s}\narchitecture: {s}\n", .{
        path,
        result.kind.label(),
        result.architecture.label(),
    });
    if (result.kind == .static_elf or result.kind == .dynamic_elf) {
        try writer.print("pie: {s}\nexecutable-stack: {s}\n", .{
            if (result.is_pie) "yes" else "no",
            if (result.has_executable_stack) "yes" else "no",
        });
    }
    if (result.python_lock) |lock| try writer.print("lock: {s}\n", .{lock});
    if (result.node_lock) |lock| try writer.print("lock: {s}\n", .{lock});
}

fn parseScanner(value: []const u8) ?tailor.security.Scanner {
    if (std.mem.eql(u8, value, "osv")) return .osv;
    if (std.mem.eql(u8, value, "grype")) return .grype;
    if (std.mem.eql(u8, value, "trivy")) return .trivy;
    return null;
}

fn explainInspectionError(err: anyerror) error{TailorFailed} {
    switch (err) {
        error.UnsupportedArtifact => fail("unsupported input; expected a Linux ELF, executable JAR, locked Node.js project, or hash-locked Python project", .{}) catch {},
        error.NodeLockInvalid => fail("Node.js project needs package-lock.json v2/v3 with exact versions and strong integrity hashes", .{}) catch {},
        error.PythonLockMissing => fail("Python project needs requirements.lock (or requirements.txt) with exact pins and sha256 hashes", .{}) catch {},
        error.NotPortablePath => fail("input must be a relative path without '..'", .{}) catch {},
        error.UnsupportedElfEndian => fail("big-endian ELF is not supported yet", .{}) catch {},
        error.UnsupportedElfMachine => fail("ELF architecture is not supported", .{}) catch {},
        error.UnsupportedElfType, error.InvalidElf => fail("invalid or non-executable ELF", .{}) catch {},
        error.EmptyFile => fail("input file is empty", .{}) catch {},
        else => fail("could not inspect input: {s}", .{@errorName(err)}) catch {},
    }
    return error.TailorFailed;
}

fn explainScanError(err: anyerror) error{TailorFailed} {
    switch (err) {
        error.ScanFailed => fail("security gate failed: scanner found policy violations or could not complete", .{}) catch {},
        error.ScannerCrashed => fail("security scanner terminated unexpectedly", .{}) catch {},
        error.CatalogFailed => fail("Grype image scans require a working Syft installation", .{}) catch {},
        error.InvalidScanReport => fail("invalid scanner JSON; inspect .tailor-reports", .{}) catch {},
        error.ScanCoverageMissing => fail("image scan has no complete package inventory", .{}) catch {},
        error.StaleDatabase => fail("scanner database is invalid, stale, or dated in the future", .{}) catch {},
        else => fail("security scanner error: {s}", .{@errorName(err)}) catch {},
    }
    return error.TailorFailed;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "help") or std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

fn fail(comptime format: []const u8, args: anytype) error{TailorFailed} {
    std.debug.print("tailor: " ++ format ++ "\n", args);
    return error.TailorFailed;
}

const NativeOptions = struct {
    sysroot: ?[]const u8 = null,
    source: ?[]const u8 = null,
    commands: std.ArrayList([]const u8) = .empty,
    libraries: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *NativeOptions, allocator: std.mem.Allocator) void {
        self.commands.deinit(allocator);
        self.libraries.deinit(allocator);
    }

    fn consume(self: *NativeOptions, allocator: std.mem.Allocator, option: []const u8, args: []const []const u8, index: *usize) !bool {
        const root = std.mem.eql(u8, option, "--sysroot");
        const command = std.mem.eql(u8, option, "--exec");
        const library = std.mem.eql(u8, option, "--library");
        const source = std.mem.eql(u8, option, "--source");
        if (!root and !command and !library and !source) return false;
        if (index.* >= args.len) return fail("missing value for {s}", .{option});
        const value = args[index.*];
        index.* += 1;
        if (root) self.sysroot = value else if (source) self.source = value else if (command) try self.commands.append(allocator, value) else try self.libraries.append(allocator, value);
        return true;
    }

    fn resolve(self: NativeOptions, allocator: std.mem.Allocator, io: Io, input: []const u8) !?tailor.dependencies.Resolver {
        const root = self.sysroot orelse {
            if (self.commands.items.len > 0 or self.libraries.items.len > 0 or self.source != null) return fail("--exec, --library, and --source require --sysroot", .{});
            return null;
        };
        var resolver = try tailor.dependencies.Resolver.init(allocator, io, root);
        errdefer resolver.deinit(io);
        const stat = try Io.Dir.cwd().statFile(io, input, .{});
        if (stat.kind == .file) try resolver.application(io, input);
        for (self.commands.items) |command| try resolver.command(io, command);
        if (self.source) |source| try resolver.discover(io, source, self.commands.items.len > 0) else if (stat.kind == .directory) try resolver.discover(io, input, self.commands.items.len > 0);
        for (self.libraries.items) |library| try resolver.library(io, library);
        try resolver.packageInventory(io);
        try resolver.materialize(io);
        return resolver;
    }
};
