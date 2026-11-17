//! Tailor's public API.

pub const version = @import("build_options").version;

pub const artifact = @import("artifact.zig");
pub const dockerfile = @import("dockerfile.zig");
pub const generated_file = @import("generated_file.zig");
pub const pipeline = @import("pipeline.zig");
pub const security = @import("security.zig");
pub const snapshot = @import("snapshot.zig");
pub const runtime = @import("runtime.zig");
pub const scan_report = @import("scan_report.zig");
pub const elf = @import("elf.zig");
pub const dependencies = @import("dependencies.zig");
pub const discovery = @import("discovery.zig");
pub const explanation = @import("explanation.zig");

test {
    _ = artifact;
    _ = dockerfile;
    _ = generated_file;
    _ = pipeline;
    _ = security;
    _ = snapshot;
    _ = runtime;
    _ = scan_report;
    _ = elf;
    _ = dependencies;
    _ = discovery;
    _ = explanation;
}
