const std = @import("std");
const artifact = @import("artifact.zig");
const dependencies = @import("dependencies.zig");

/// Describe observed evidence, never claim that static discovery is complete.
pub fn render(allocator: std.mem.Allocator, input: []const u8, inspection: artifact.Inspection, resolver: ?*const dependencies.Resolver, source_analyzed: bool) ![]u8 {
    const files: []const dependencies.File = if (resolver) |r| r.files.items else &.{};
    const edges: []const dependencies.Edge = if (resolver) |r| r.edges.items else &.{};
    const unresolved: []const dependencies.UnresolvedCall = if (resolver) |r| r.unresolved_calls.items else &.{};
    const strategy: []const u8 = switch (inspection.kind) {
        .static_elf => "scratch",
        .dynamic_elf => if (files.len > 0) "scratch with resolved native closure" else "digest-pinned runtime required; native closure not resolved",
        .jar => "digest-pinned Java runtime required",
        .node_project => "digest-pinned Node builder and runtime required",
        .python_project => "digest-pinned Python builder and runtime required",
    };
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = 1,
        .input = input,
        .artifact = inspection,
        .runtime_strategy = strategy,
        .source_analyzed = source_analyzed,
        .analysis_complete = false,
        .unresolved_calls = unresolved,
        .files = files,
        .dependency_edges = edges,
        .security_scan_performed = false,
        .limitations = [_][]const u8{
            "Compiled artifacts cannot reveal every subprocess or runtime-loaded library.",
            "Source discovery is syntactic; aliases, reflection, helper script internals and dlopen need declarations and workload tests.",
            "Explicit --exec declarations do not prove which commands a dynamic call will select.",
            "Runtime bases and installed Java/JNI, Node and Python native modules require separate validation.",
            "This report describes artifact and sysroot dependencies, not the full contents of a supplied base image.",
            "Missing libraries, incompatible symbols and unresolved literal commands fail report generation.",
        },
    }, .{ .whitespace = .indent_2 });
}

test "explanation without a sysroot reports uncertainty and does not certify security" {
    const bytes = try render(std.testing.allocator, "app.jar", .{ .kind = .jar }, null, false);
    defer std.testing.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    try std.testing.expect(!parsed.value.object.get("analysis_complete").?.bool);
    try std.testing.expect(!parsed.value.object.get("security_scan_performed").?.bool);
    try std.testing.expectEqualStrings("digest-pinned Java runtime required", parsed.value.object.get("runtime_strategy").?.string);
}
