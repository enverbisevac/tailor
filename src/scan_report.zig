const std = @import("std");
pub const Summary = struct { packages: usize = 0, vulnerabilities: usize = 0, suppressed: usize = 0, inventory_complete: bool = true };

pub fn summarize(scanner: []const u8, root: std.json.Value) !Summary {
    if (root != .object) return error.InvalidScanReport;
    var result: Summary = .{};
    if (std.mem.eql(u8, scanner, "grype")) {
        const matches = try array(root, "matches");
        result.vulnerabilities = matches.len;
        if (root.object.get("artifacts")) |_| {
            result.packages = (try array(root, "artifacts")).len;
        } else {
            // Current Grype JSON reports contain matched artifacts only. They
            // cannot prove that a clean result included any package inventory.
            result.inventory_complete = false;
            var seen: std.StringHashMap(void) = .init(std.heap.page_allocator);
            defer seen.deinit();
            for (matches) |match| {
                if (match != .object) return error.InvalidScanReport;
                const package = match.object.get("artifact") orelse return error.InvalidScanReport;
                if (package != .object) return error.InvalidScanReport;
                const id = package.object.get("id") orelse return error.InvalidScanReport;
                if (id != .string) return error.InvalidScanReport;
                try seen.put(id.string, {});
            }
            result.packages = seen.count();
        }
        if (root.object.get("ignoredMatches")) |ignored| {
            if (ignored != .array) return error.InvalidScanReport;
            result.suppressed = ignored.array.items.len;
        }
        // Missing self-identification can indicate truncated or unrelated JSON.
        const descriptor = root.object.get("descriptor") orelse return error.InvalidScanReport;
        if (descriptor != .object) return error.InvalidScanReport;
    } else if (std.mem.eql(u8, scanner, "trivy")) {
        const schema = root.object.get("SchemaVersion") orelse return error.InvalidScanReport;
        if (schema != .integer or schema.integer != 2) return error.InvalidScanReport;
        // Trivy omits Results (or emits null) when no analyzers find packages.
        // Source scans can legitimately be empty; image coverage is gated later.
        for (try optionalArray(root, "Results")) |item| {
            if (item != .object) return error.InvalidScanReport;
            result.packages += (try optionalArray(item, "Packages")).len;
            result.vulnerabilities += (try optionalArray(item, "Vulnerabilities")).len;
        }
    } else if (std.mem.eql(u8, scanner, "osv-scanner")) {
        for (try array(root, "results")) |item| {
            for (try array(item, "packages")) |package| {
                result.packages += 1;
                result.vulnerabilities += (try optionalArray(package, "vulnerabilities")).len;
            }
        }
    } else return error.InvalidScanReport;
    return result;
}

fn array(root: std.json.Value, key: []const u8) ![]const std.json.Value {
    if (root != .object) return error.InvalidScanReport;
    const value = root.object.get(key) orelse return error.InvalidScanReport;
    if (value != .array) return error.InvalidScanReport;
    return value.array.items;
}

fn optionalArray(root: std.json.Value, key: []const u8) ![]const std.json.Value {
    if (root != .object) return error.InvalidScanReport;
    const value = root.object.get(key) orelse return &.{};
    if (value == .null) return &.{};
    if (value != .array) return error.InvalidScanReport;
    return value.array.items;
}

pub fn validateGrypeFreshness(root: std.json.Value, now: i64) !void {
    const descriptor = try objectField(root, "descriptor");
    const db = try objectField(descriptor, "db");
    const status = if (db.object.get("status")) |status| status else db;
    if (status != .object) return error.InvalidScanReport;
    const valid = status.object.get("valid") orelse return error.InvalidScanReport;
    if (valid != .bool or !valid.bool) return error.StaleDatabase;
    const built = status.object.get("built") orelse return error.InvalidScanReport;
    if (built != .string) return error.InvalidScanReport;
    const timestamp = try utcSeconds(built.string);
    if (timestamp > now + 300 or now - timestamp > 120 * 3600) return error.StaleDatabase;
}

fn objectField(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidScanReport;
    const result = value.object.get(key) orelse return error.InvalidScanReport;
    if (result != .object) return error.InvalidScanReport;
    return result;
}

fn utcSeconds(value: []const u8) !i64 {
    if (value.len < 20 or value[4] != '-' or value[7] != '-' or value[10] != 'T' or value[13] != ':' or value[16] != ':' or value[value.len - 1] != 'Z') return error.InvalidScanReport;
    if (value.len > 20) {
        if (value.len < 22 or value[19] != '.') return error.InvalidScanReport;
        for (value[20 .. value.len - 1]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidScanReport;
    }
    const year = std.fmt.parseInt(u16, value[0..4], 10) catch return error.InvalidScanReport;
    const month = std.fmt.parseInt(u8, value[5..7], 10) catch return error.InvalidScanReport;
    const day = std.fmt.parseInt(u8, value[8..10], 10) catch return error.InvalidScanReport;
    const hour = std.fmt.parseInt(u8, value[11..13], 10) catch return error.InvalidScanReport;
    const minute = std.fmt.parseInt(u8, value[14..16], 10) catch return error.InvalidScanReport;
    const second = std.fmt.parseInt(u8, value[17..19], 10) catch return error.InvalidScanReport;
    if (year < 1970 or month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or second > 59) return error.InvalidScanReport;
    if (day > std.time.epoch.getDaysInMonth(year, @fromBackingInt(@intCast(month)))) return error.InvalidScanReport;
    var days: i64 = 0;
    for (1970..year) |y| days += std.time.epoch.getDaysInYear(@intCast(y));
    for (1..month) |m| days += std.time.epoch.getDaysInMonth(year, @fromBackingInt(@intCast(m)));
    return (days + day - 1) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

test "Grype database timestamps enforce freshness and reject future dates" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"descriptor":{"db":{"status":{"valid":true,"built":"2026-11-03T00:00:00Z"}}}}
    , .{});
    defer parsed.deinit();
    const built = try utcSeconds("2026-11-03T00:00:00Z");
    try validateGrypeFreshness(parsed.value, built + 3600);
    try std.testing.expectError(error.StaleDatabase, validateGrypeFreshness(parsed.value, built + 121 * 3600));
    try std.testing.expectError(error.StaleDatabase, validateGrypeFreshness(parsed.value, built - 600));
    try std.testing.expectError(error.InvalidScanReport, utcSeconds("2026-02-30T00:00:00Z"));
}

test "structured reports count findings independently of scanner exit status" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"artifacts":[{"name":"git"}],"matches":[{"vulnerability":{"id":"CVE-test"}}],"ignoredMatches":[],"descriptor":{"version":"test"}}
    , .{});
    defer parsed.deinit();
    const summary = try summarize("grype", parsed.value);
    try std.testing.expectEqual(@as(usize, 1), summary.packages);
    try std.testing.expectEqual(@as(usize, 1), summary.vulnerabilities);
    try std.testing.expectError(error.InvalidScanReport, summarize("trivy", parsed.value));
}

test "current Grype reports do not imply a complete inventory" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"matches":[{"artifact":{"id":"git"}},{"artifact":{"id":"git"}}],"descriptor":{"name":"grype"}}
    , .{});
    defer parsed.deinit();
    const summary = try summarize("grype", parsed.value);
    try std.testing.expectEqual(@as(usize, 1), summary.packages);
    try std.testing.expectEqual(@as(usize, 2), summary.vulnerabilities);
    try std.testing.expect(!summary.inventory_complete);
}

test "Trivy complete inventory and OSV malformed reports" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"SchemaVersion":2,"Results":[{"Packages":[{"Name":"git"}],"Vulnerabilities":null}]}
    , .{});
    defer parsed.deinit();
    const summary = try summarize("trivy", parsed.value);
    try std.testing.expectEqual(@as(usize, 1), summary.packages);
    try std.testing.expectEqual(@as(usize, 0), summary.vulnerabilities);
    try std.testing.expectError(error.InvalidScanReport, summarize("osv-scanner", parsed.value));
}

test "Trivy empty source reports omit or null Results but reject wrong types" {
    for ([_][]const u8{
        \\{"SchemaVersion":2,"ArtifactType":"filesystem"}
        ,
        \\{"SchemaVersion":2,"Results":null}
        ,
    }) |bytes| {
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
        defer parsed.deinit();
        const summary = try summarize("trivy", parsed.value);
        try std.testing.expectEqual(@as(usize, 0), summary.packages);
        try std.testing.expectEqual(@as(usize, 0), summary.vulnerabilities);
    }
    var invalid = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"SchemaVersion":2,"Results":{}}
    , .{});
    defer invalid.deinit();
    try std.testing.expectError(error.InvalidScanReport, summarize("trivy", invalid.value));
}
