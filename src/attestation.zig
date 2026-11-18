const std = @import("std");
const Io = std.Io;
const lockfile = @import("lockfile.zig");
const security = @import("security.zig");
const smoke = @import("smoke.zig");

const image_manifest_type = "application/vnd.oci.image.manifest.v1+json";
pub const Descriptor = struct { mediaType: []const u8, digest: []const u8, size: u64 };
const Tagged = struct { mediaType: []const u8, digest: []const u8, size: u64, annotations: struct { @"org.opencontainers.image.ref.name": []const u8 } };
const Resource = struct { name: []const u8, digest: struct { sha256: []const u8 } };
const SourceObject = struct { digest: []const u8, bytes: []const u8, media_type: []const u8 };

/// Export a runnable OCI image with SBOM/provenance subject manifests. No registry
/// writes occur. Failure leaves the requested Docker tag unpromoted.
pub fn exportImage(allocator: std.mem.Allocator, io: Io, image_id: []const u8, plan_json: []const u8, smoke_result: smoke.Result, scanner: security.Scanner, environment: ?*const std.process.Environ.Map, started_at: i64) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var plan = try std.json.parseFromSlice(lockfile.Plan, a, plan_json, .{});
    defer plan.deinit();
    var safe_environment = try security.scannerEnvironment(a, environment);
    defer safe_environment.deinit();
    const syft_version = try run(a, io, &.{ "syft", "version" }, &safe_environment);
    const skopeo_version = try run(a, io, &.{ "skopeo", "--version" }, &safe_environment);
    const scanner_version = try run(a, io, &.{ scanner.command(), "--version" }, &safe_environment);
    var temporary = try @import("snapshot.zig").Snapshot.init(a, io);
    defer temporary.deinit(io);
    const archive = try temporary.joined("image.tar");
    _ = try run(a, io, &.{ "docker", "image", "save", "--output", archive, image_id }, null);
    const exported = try readDockerConfig(a, io, archive, image_id, plan.value.config.platform);
    const original_config = exported.config;
    const source = try std.fmt.allocPrint(a, "{s}:{s}", .{ if (exported.oci) "oci-archive" else "docker-archive", archive });
    const policy = try temporary.joined("syft.yaml");
    try temporary.dir.writeFile(io, .{ .sub_path = "syft.yaml", .data = "", .flags = .{ .exclusive = true } });
    const sbom = try run(a, io, &.{ "syft", "scan", source, "--config", policy, "--output", "cyclonedx-json" }, &safe_environment);
    var parsed_sbom = try std.json.parseFromSlice(std.json.Value, a, sbom, .{});
    defer parsed_sbom.deinit();
    if (!std.mem.eql(u8, try string(parsed_sbom.value, "bomFormat"), "CycloneDX")) return error.InvalidAttestation;
    const components = try array(parsed_sbom.value, "components");
    if (components.len == 0) return error.InvalidAttestation;

    Io.Dir.cwd().createDir(io, ".tailor-reports", .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const reports = try Io.Dir.cwd().openDir(io, ".tailor-reports", .{ .follow_symlinks = false });
    defer reports.close(io);
    var nonce: [16]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try std.fmt.allocPrint(a, "build-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    try reports.createDir(io, name, .default_dir);
    var complete = false;
    const directory = try std.fmt.allocPrint(a, ".tailor-reports/{s}", .{name});
    const work = try reports.openDir(io, name, .{ .follow_symlinks = false });
    defer work.close(io);
    defer if (!complete) {
        work.writeFile(io, .{ .sub_path = "incomplete.json", .data = "{\"complete\":false}\n", .flags = .{ .exclusive = true } }) catch {};
        std.debug.print("incomplete evidence retained for diagnosis: {s}\n", .{directory});
    };
    const layout_path = try std.fmt.allocPrint(a, "{s}/oci", .{directory});
    const destination = try std.fmt.allocPrint(a, "oci:{s}:image", .{layout_path});
    _ = try run(a, io, &.{ "skopeo", "copy", "--format", "oci", source, destination }, &safe_environment);
    const layout = try work.openDir(io, "oci", .{ .follow_symlinks = false });
    defer layout.close(io);
    const source_chain = try a.alloc([]const u8, exported.objects.len);
    for (exported.objects, source_chain) |object, *digest| {
        const stored = try writeBlob(a, io, layout, object.bytes, object.media_type);
        if (!std.mem.eql(u8, stored.digest, object.digest)) return error.InvalidAttestation;
        digest.* = object.digest;
    }
    const index_bytes = try layout.readFileAlloc(io, "index.json", a, .limited(1024 * 1024));
    var index = try std.json.parseFromSlice(std.json.Value, a, index_bytes, .{});
    defer index.deinit();
    const manifests = try array(index.value, "manifests");
    if (manifests.len != 1) return error.InvalidAttestation;
    var image = try descriptor(manifests[0]);
    if (!std.mem.eql(u8, image.mediaType, image_manifest_type)) return error.InvalidAttestation;
    const manifest_bytes = try readBlob(a, io, layout, image);
    var manifest = try std.json.parseFromSlice(std.json.Value, a, manifest_bytes, .{});
    defer manifest.deinit();
    var config = try descriptor(try field(manifest.value, "config"));
    const config_bytes = try readBlob(a, io, layout, config);
    var converted_config = try std.json.parseFromSlice(std.json.Value, a, config_bytes, .{});
    defer converted_config.deinit();
    var image_config = try std.json.parseFromSlice(std.json.Value, a, original_config, .{});
    defer image_config.deinit();
    const before = try array(try field(image_config.value, "rootfs"), "diff_ids");
    const after = try array(try field(converted_config.value, "rootfs"), "diff_ids");
    const layer_values = try array(manifest.value, "layers");
    if (before.len != after.len or before.len != layer_values.len) {
        std.debug.print("OCI conversion layer counts differ: {d}/{d}/{d}\n", .{ before.len, after.len, layer_values.len });
        return error.InvalidAttestation;
    }
    for (before, after) |left, right| {
        if (left != .string or right != .string or !std.mem.eql(u8, left.string, right.string)) {
            std.debug.print("OCI conversion changed a rootfs layer identity\n", .{});
            return error.InvalidAttestation;
        }
    }
    // Conversion reserializes Docker configuration JSON. Restore the original
    // content-addressed bytes, preserving runtime settings and rootfs diff IDs.
    config = try writeBlob(a, io, layout, original_config, "application/vnd.oci.image.config.v1+json");
    if (!std.mem.eql(u8, config.digest, exported.config_digest)) return error.InvalidAttestation;
    const layers = try a.alloc(Descriptor, layer_values.len);
    for (layer_values, layers) |value, *out| out.* = try descriptor(value);
    const restored_manifest = try std.json.Stringify.valueAlloc(a, .{
        .schemaVersion = 2,
        .mediaType = image_manifest_type,
        .config = config,
        .layers = layers,
    }, .{ .whitespace = .indent_2 });
    image = try writeBlob(a, io, layout, restored_manifest, image_manifest_type);
    const variant = if (image_config.value == .object) image_config.value.object.get("variant") else null;
    const actual_platform = if (variant) |value| actual: {
        if (value != .string) return error.InvalidAttestation;
        if (value.string.len == 0) break :actual try std.fmt.allocPrint(a, "{s}/{s}", .{ try string(image_config.value, "os"), try string(image_config.value, "architecture") });
        break :actual try std.fmt.allocPrint(a, "{s}/{s}/{s}", .{ try string(image_config.value, "os"), try string(image_config.value, "architecture"), value.string });
    } else try std.fmt.allocPrint(a, "{s}/{s}", .{ try string(image_config.value, "os"), try string(image_config.value, "architecture") });
    const baseline_arm64 = std.mem.eql(u8, plan.value.config.platform, "linux/arm64") and std.mem.eql(u8, actual_platform, "linux/arm64/v8");
    if (!std.mem.eql(u8, plan.value.config.platform, "unspecified") and
        !std.mem.eql(u8, plan.value.config.platform, actual_platform) and !baseline_arm64) return error.InvalidAttestation;
    try work.writeFile(io, .{ .sub_path = "tailor.lock", .data = plan_json, .flags = .{ .exclusive = true } });
    try work.writeFile(io, .{ .sub_path = "sbom.cdx.json", .data = sbom, .flags = .{ .exclusive = true } });
    const build_report = try std.json.Stringify.valueAlloc(a, .{
        .schema_version = 1,
        .image_id = image_id,
        .docker_config_digest = exported.config_digest,
        .source_descriptor_chain = source_chain,
        .oci_manifest = image.digest,
        .platform = actual_platform,
        .plan_sha256 = lockfile.hash(plan_json),
        .scanner = scanner.command(),
        .vulnerability_gates_passed = true,
        .smoke = smoke_result,
        .started_at_unix = started_at,
        .finished_at_unix = Io.Clock.real.now(io).toSeconds(),
        .signed = false,
    }, .{ .whitespace = .indent_2 });
    try work.writeFile(io, .{ .sub_path = "build-report.json", .data = build_report, .flags = .{ .exclusive = true } });
    var resources: std.ArrayList(Resource) = .empty;
    if (plan.value.config.smoke.http_path != null) {
        const probe_image = plan.value.config.smoke.probe_image orelse return error.InvalidAttestation;
        const position = std.mem.lastIndexOf(u8, probe_image, "@sha256:") orelse return error.InvalidAttestation;
        try resources.append(a, .{ .name = probe_image, .digest = .{ .sha256 = probe_image[position + 8 ..] } });
    }
    for (plan.value.files) |file| try resources.append(a, .{ .name = file.path, .digest = .{ .sha256 = try a.dupe(u8, &file.sha256) } });
    for (plan.value.native_files) |file| try resources.append(a, .{ .name = file.destination, .digest = .{ .sha256 = try a.dupe(u8, &file.sha256) } });
    for ([_]?[]const u8{ plan.value.config.base, plan.value.config.builder_base }) |base| if (base) |value| {
        const position = std.mem.lastIndexOf(u8, value, "@sha256:") orelse return error.InvalidAttestation;
        try resources.append(a, .{ .name = value, .digest = .{ .sha256 = value[position + 8 ..] } });
    };
    const provenance = try std.json.Stringify.valueAlloc(a, .{
        ._type = "https://in-toto.io/Statement/v1",
        .subject = .{.{ .name = "image", .digest = .{ .sha256 = image.digest[7..] } }},
        .predicateType = "https://slsa.dev/provenance/v1",
        .predicate = .{
            .buildDefinition = .{
                .buildType = "https://github.com/enverbisevac/tailor/blob/main/docs/build-type-v1.md",
                .externalParameters = plan.value.config,
                .internalParameters = .{ .dockerfile_sha256 = plan.value.dockerfile_sha256 },
                .resolvedDependencies = resources.items,
            },
            .runDetails = .{
                .builder = .{ .id = "https://github.com/enverbisevac/tailor", .version = .{ .tailor = @import("build_options").version, .syft = syft_version, .skopeo = skopeo_version, .scanner = scanner_version } },
                .metadata = .{ .invocationId = name },
                .byproducts = .{
                    .{ .name = "tailor.lock", .digest = .{ .sha256 = lockfile.hash(plan_json) } },
                    .{ .name = "build-report.json", .digest = .{ .sha256 = lockfile.hash(build_report) } },
                },
            },
        },
    }, .{ .whitespace = .indent_2 });
    try work.writeFile(io, .{ .sub_path = "provenance.json", .data = provenance, .flags = .{ .exclusive = true } });
    const sbom_manifest = try attach(a, io, layout, image, sbom, "application/vnd.cyclonedx+json");
    const provenance_manifest = try attach(a, io, layout, image, provenance, "application/vnd.in-toto+json");
    const new_index = try std.json.Stringify.valueAlloc(a, .{
        .schemaVersion = 2,
        .mediaType = "application/vnd.oci.image.index.v1+json",
        .manifests = [_]Tagged{ tagged(image, "image"), tagged(sbom_manifest, "sbom"), tagged(provenance_manifest, "provenance") },
    }, .{ .whitespace = .indent_2 });
    try layout.writeFile(io, .{ .sub_path = "index.json", .data = new_index });
    complete = true;
    return allocator.dupe(u8, directory);
}

pub fn attach(a: std.mem.Allocator, io: Io, layout: Io.Dir, image: Descriptor, bytes: []const u8, media_type: []const u8) !Descriptor {
    const layer = try writeBlob(a, io, layout, bytes, media_type);
    const config = try writeBlob(a, io, layout, "{}", "application/vnd.oci.empty.v1+json");
    const manifest = try std.json.Stringify.valueAlloc(a, .{
        .schemaVersion = 2,
        .mediaType = image_manifest_type,
        .artifactType = media_type,
        .config = config,
        .layers = .{layer},
        .subject = image,
    }, .{ .whitespace = .indent_2 });
    defer a.free(manifest);
    return writeBlob(a, io, layout, manifest, image_manifest_type);
}

fn tagged(value: Descriptor, name: []const u8) Tagged {
    return .{ .mediaType = value.mediaType, .digest = value.digest, .size = value.size, .annotations = .{ .@"org.opencontainers.image.ref.name" = name } };
}

fn readDockerConfig(a: std.mem.Allocator, io: Io, archive: []const u8, image_id: []const u8, platform: []const u8) !struct { config: []u8, config_digest: []const u8, oci: bool, objects: []const SourceObject } {
    var digest = image_id;
    var objects: std.ArrayList(SourceObject) = .empty;
    for (0..8) |_| {
        const object = try readArchiveObject(a, io, archive, digest);
        var parsed = try std.json.parseFromSlice(std.json.Value, a, object.config, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidAttestation;
        const media_type = if (parsed.value.object.get("mediaType")) |value| (if (value == .string) value.string else return error.InvalidAttestation) else "application/vnd.oci.image.config.v1+json";
        try objects.append(a, .{ .digest = digest, .bytes = object.config, .media_type = media_type });
        if (parsed.value.object.get("rootfs") != null) return .{ .config = object.config, .config_digest = digest, .oci = object.oci, .objects = objects.items };
        if (parsed.value.object.get("config")) |config| {
            digest = (try descriptor(config)).digest;
            continue;
        }
        const manifests = try array(parsed.value, "manifests");
        var selected: ?[]const u8 = null;
        for (manifests) |candidate| {
            if (candidate != .object) return error.InvalidAttestation;
            const candidate_platform = candidate.object.get("platform");
            if (candidate_platform) |p| {
                if (!std.mem.eql(u8, try string(p, "os"), "linux")) continue;
                const arch = try string(p, "architecture");
                const prefix = try std.fmt.allocPrint(a, "linux/{s}", .{arch});
                if (!std.mem.eql(u8, platform, "unspecified") and !std.mem.eql(u8, platform, prefix) and
                    !(std.mem.eql(u8, platform, "linux/arm/v7") and std.mem.eql(u8, arch, "arm"))) continue;
            } else if (manifests.len != 1) continue;
            if (selected != null) return error.InvalidAttestation;
            selected = (try descriptor(candidate)).digest;
        }
        digest = selected orelse return error.InvalidAttestation;
    }
    return error.InvalidAttestation;
}

fn readArchiveObject(a: std.mem.Allocator, io: Io, archive: []const u8, image_id: []const u8) !struct { config: []u8, oci: bool } {
    if (image_id.len != 71 or !std.mem.startsWith(u8, image_id, "sha256:")) return error.InvalidAttestation;
    for (image_id[7..]) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return error.InvalidAttestation;
    const file = try Io.Dir.cwd().openFile(io, archive, .{ .follow_symlinks = false });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader.interface, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    const oci_name = try std.fmt.allocPrint(a, "blobs/sha256/{s}", .{image_id[7..]});
    const docker_name = try std.fmt.allocPrint(a, "{s}.json", .{image_id[7..]});
    var config: ?[]u8 = null;
    var oci = false;
    while (try iterator.next()) |entry| {
        var name = entry.name;
        while (std.mem.startsWith(u8, name, "./")) name = name[2..];
        if (std.mem.eql(u8, name, "oci-layout") and entry.kind == .file) oci = true;
        if (config != null and oci) return .{ .config = config.?, .oci = true };
        if (entry.kind != .file or (!std.mem.eql(u8, name, oci_name) and !std.mem.eql(u8, name, docker_name))) continue;
        if (entry.size > 16 * 1024 * 1024) return error.InvalidAttestation;
        const bytes = try a.alloc(u8, @intCast(entry.size));
        try reader.interface.readSliceAll(bytes);
        iterator.unread_file_bytes = 0;
        if (!std.mem.eql(u8, &lockfile.hash(bytes), image_id[7..])) return error.InvalidAttestation;
        config = bytes;
        if (oci) return .{ .config = bytes, .oci = true };
    }
    return .{ .config = config orelse return error.InvalidAttestation, .oci = false };
}

fn writeBlob(a: std.mem.Allocator, io: Io, layout: Io.Dir, bytes: []const u8, media_type: []const u8) !Descriptor {
    const hash = lockfile.hash(bytes);
    const path = try std.fmt.allocPrint(a, "blobs/sha256/{s}", .{hash});
    defer a.free(path);
    try layout.createDirPath(io, "blobs/sha256");
    layout.writeFile(io, .{ .sub_path = path, .data = bytes, .flags = .{ .exclusive = true } }) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try layout.readFileAlloc(io, path, a, .limited(bytes.len + 1));
            defer a.free(existing);
            if (!std.mem.eql(u8, bytes, existing)) return error.InvalidAttestation;
        },
        else => return err,
    };
    return .{ .mediaType = media_type, .digest = try std.fmt.allocPrint(a, "sha256:{s}", .{hash}), .size = bytes.len };
}

fn readBlob(a: std.mem.Allocator, io: Io, layout: Io.Dir, value: Descriptor) ![]u8 {
    if (value.digest.len != 71 or !std.mem.startsWith(u8, value.digest, "sha256:") or value.size > 16 * 1024 * 1024) return error.InvalidAttestation;
    for (value.digest[7..]) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return error.InvalidAttestation;
    const path = try std.fmt.allocPrint(a, "blobs/sha256/{s}", .{value.digest[7..]});
    defer a.free(path);
    const bytes = try layout.readFileAlloc(io, path, a, .limited(16 * 1024 * 1024));
    errdefer a.free(bytes);
    if (bytes.len != value.size or !std.mem.eql(u8, &lockfile.hash(bytes), value.digest[7..])) return error.InvalidAttestation;
    return bytes;
}

fn descriptor(value: std.json.Value) !Descriptor {
    const size = try field(value, "size");
    if (size != .integer or size.integer < 0) return error.InvalidAttestation;
    return .{ .mediaType = try string(value, "mediaType"), .digest = try string(value, "digest"), .size = @intCast(size.integer) };
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidAttestation;
    return value.object.get(name) orelse error.InvalidAttestation;
}

fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidAttestation;
    return item.string;
}

fn array(value: std.json.Value, name: []const u8) ![]const std.json.Value {
    const item = try field(value, name);
    if (item != .array) return error.InvalidAttestation;
    return item.array.items;
}

fn run(a: std.mem.Allocator, io: Io, argv: []const []const u8, environment: ?*const std.process.Environ.Map) ![]u8 {
    const result = try std.process.run(a, io, .{
        .argv = argv,
        .environ_map = environment,
        .stdout_limit = .limited(64 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } },
    });
    defer a.free(result.stderr);
    errdefer a.free(result.stdout);
    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }
    std.debug.print("attestation tool failed: {s}\n", .{result.stderr});
    return error.AttestationFailed;
}

test "OCI evidence manifests bind immutable subjects and payload bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const fake_hash: [64]u8 = @splat('a');
    const subject: Descriptor = .{ .mediaType = image_manifest_type, .digest = "sha256:" ++ fake_hash, .size = 123 };
    const attached = try attach(a, std.testing.io, directory.dir, subject, "{\"bomFormat\":\"CycloneDX\"}", "application/vnd.cyclonedx+json");
    const bytes = try readBlob(a, std.testing.io, directory.dir, attached);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(subject.digest, try string(try field(parsed.value, "subject"), "digest"));
    try std.testing.expectEqualStrings("application/vnd.cyclonedx+json", try string(parsed.value, "artifactType"));
    const layers = try array(parsed.value, "layers");
    _ = try readBlob(a, std.testing.io, directory.dir, try descriptor(layers[0]));
    // Both artifacts share the empty config blob; existing CAS blobs must be
    // verified and reused rather than rejected at the exact read limit.
    const second = try attach(a, std.testing.io, directory.dir, subject, "{\"_type\":\"statement\"}", "application/vnd.in-toto+json");
    _ = try readBlob(a, std.testing.io, directory.dir, second);
}
