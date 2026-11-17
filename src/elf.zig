const std = @import("std");

pub const Metadata = struct {
    machine: u16,
    bits: u8,
    flags: u32,
    interpreter: ?[]const u8 = null,
    needed: []const []const u8,
    runpath: ?[]const u8 = null,
    rpath: ?[]const u8 = null,
    executable_stack: bool = false,
    version_needs: []const VersionNeed = &.{},
    provided_versions: []const []const u8 = &.{},
};

pub const VersionNeed = struct { library: []const u8, version: []const u8 };

/// Slices borrow from bytes; the needed list belongs to allocator. No code runs.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Metadata {
    if (bytes.len < 52 or !std.mem.eql(u8, bytes[0..4], "\x7fELF") or bytes[6] != 1) return error.InvalidElf;
    const bits: u8 = switch (bytes[4]) {
        1 => 32,
        2 => 64,
        else => return error.InvalidElf,
    };
    if (bytes[5] != 1) return error.UnsupportedElfEndian;
    const phoff = try uint(bytes, if (bits == 64) 32 else 28, if (bits == 64) 8 else 4);
    const phsize = try uint(bytes, if (bits == 64) 54 else 42, 2);
    const phnum = try uint(bytes, if (bits == 64) 56 else 44, 2);
    if (phsize < (if (bits == 64) @as(u64, 56) else 32) or phnum > 4096) return error.InvalidElf;
    _ = try range(bytes, phoff, std.math.mul(u64, phsize, phnum) catch return error.InvalidElf);
    var result: Metadata = .{ .machine = @intCast(try uint(bytes, 18, 2)), .bits = bits, .flags = @intCast(try uint(bytes, if (bits == 64) 48 else 36, 4)), .needed = &.{} };
    var dynamic: ?[]const u8 = null;
    for (0..@intCast(phnum)) |i| {
        const ph = try range(bytes, phoff + i * phsize, phsize);
        const kind = try uint(ph, 0, 4);
        if (kind == 0x6474e551) {
            const flags = try uint(ph, if (bits == 64) 4 else 24, 4);
            result.executable_stack = flags & 1 != 0;
        }
        const offset = try uint(ph, if (bits == 64) 8 else 4, if (bits == 64) 8 else 4);
        const size = try uint(ph, if (bits == 64) 32 else 16, if (bits == 64) 8 else 4);
        if (kind == 3) {
            const data = try range(bytes, offset, size);
            if (data.len < 2 or data[data.len - 1] != 0) return error.InvalidElf;
            result.interpreter = data[0 .. data.len - 1];
        } else if (kind == 2) dynamic = try range(bytes, offset, size);
    }
    const data = dynamic orelse return result;
    const word: usize = if (bits == 64) 8 else 4;
    if (data.len % (word * 2) != 0) return error.InvalidElf;
    var strtab: ?u64 = null;
    var strsize: ?u64 = null;
    var needed: std.ArrayList(u64) = .empty;
    defer needed.deinit(allocator);
    var runpath: ?u64 = null;
    var rpath: ?u64 = null;
    var verneed: ?u64 = null;
    var verneed_count: u64 = 0;
    var verdef: ?u64 = null;
    var verdef_count: u64 = 0;
    var pos: usize = 0;
    while (pos < data.len) : (pos += word * 2) {
        const tag = try uint(data, pos, word);
        const value = try uint(data, pos + word, word);
        switch (tag) {
            0 => break,
            1 => {
                if (needed.items.len >= 4096) return error.InvalidElf;
                try needed.append(allocator, value);
            },
            5 => strtab = value,
            10 => strsize = value,
            15 => rpath = value,
            29 => runpath = value,
            0x6ffffffe => verneed = value,
            0x6fffffff => verneed_count = value,
            0x6ffffffc => verdef = value,
            0x6ffffffd => verdef_count = value,
            else => {},
        }
    }
    if (needed.items.len == 0 and runpath == null and rpath == null and verneed == null and verdef == null) return result;
    const address = strtab orelse return error.InvalidElf;
    var strings: ?[]const u8 = null;
    for (0..@intCast(phnum)) |i| {
        const ph = try range(bytes, phoff + i * phsize, phsize);
        if (try uint(ph, 0, 4) != 1) continue;
        const offset = try uint(ph, if (bits == 64) 8 else 4, word);
        const vaddr = try uint(ph, if (bits == 64) 16 else 8, word);
        const size = try uint(ph, if (bits == 64) 32 else 16, word);
        if (address >= vaddr and address - vaddr < size) {
            const length = strsize orelse return error.InvalidElf;
            if (length > size - (address - vaddr)) return error.InvalidElf;
            strings = try range(bytes, std.math.add(u64, offset, address - vaddr) catch return error.InvalidElf, length);
            break;
        }
    }
    const table = strings orelse return error.InvalidElf;
    const names = try allocator.alloc([]const u8, needed.items.len);
    errdefer allocator.free(names);
    for (needed.items, 0..) |offset, i| names[i] = try cstring(table, offset);
    result.needed = names;
    if (runpath) |offset| result.runpath = try cstring(table, offset);
    if (rpath) |offset| result.rpath = try cstring(table, offset);
    var requirements: std.ArrayList(VersionNeed) = .empty;
    errdefer requirements.deinit(allocator);
    var definitions: std.ArrayList([]const u8) = .empty;
    errdefer definitions.deinit(allocator);
    if (verneed_count > 65535 or verdef_count > 65535) return error.InvalidElf;
    if (verneed) |address_needs| {
        const records = try virtualTail(bytes, bits, phoff, phsize, phnum, address_needs);
        var offset: u64 = 0;
        for (0..@intCast(verneed_count)) |i| {
            const record = try range(records, offset, 16);
            const count = try uint(record, 2, 2);
            const library = try cstring(table, try uint(record, 4, 4));
            var aux = std.math.add(u64, offset, try uint(record, 8, 4)) catch return error.InvalidElf;
            if (requirements.items.len + count > 65535) return error.InvalidElf;
            for (0..@intCast(count)) |j| {
                const entry = try range(records, aux, 16);
                try requirements.append(allocator, .{ .library = library, .version = try cstring(table, try uint(entry, 8, 4)) });
                const next = try uint(entry, 12, 4);
                if (j + 1 < count and next == 0) return error.InvalidElf;
                aux = std.math.add(u64, aux, next) catch return error.InvalidElf;
            }
            const next = try uint(record, 12, 4);
            if (i + 1 < verneed_count and next == 0) return error.InvalidElf;
            offset = std.math.add(u64, offset, next) catch return error.InvalidElf;
        }
    } else if (verneed_count != 0) return error.InvalidElf;
    if (verdef) |address_defs| {
        const records = try virtualTail(bytes, bits, phoff, phsize, phnum, address_defs);
        var offset: u64 = 0;
        for (0..@intCast(verdef_count)) |i| {
            const record = try range(records, offset, 20);
            const aux = std.math.add(u64, offset, try uint(record, 12, 4)) catch return error.InvalidElf;
            const entry = try range(records, aux, 8);
            try definitions.append(allocator, try cstring(table, try uint(entry, 0, 4)));
            const next = try uint(record, 16, 4);
            if (i + 1 < verdef_count and next == 0) return error.InvalidElf;
            offset = std.math.add(u64, offset, next) catch return error.InvalidElf;
        }
    } else if (verdef_count != 0) return error.InvalidElf;
    result.version_needs = try requirements.toOwnedSlice(allocator);
    result.provided_versions = try definitions.toOwnedSlice(allocator);
    return result;
}

fn virtualTail(bytes: []const u8, bits: u8, phoff: u64, phsize: u64, phnum: u64, address: u64) ![]const u8 {
    const word: usize = if (bits == 64) 8 else 4;
    for (0..@intCast(phnum)) |i| {
        const ph = try range(bytes, phoff + i * phsize, phsize);
        if (try uint(ph, 0, 4) != 1) continue;
        const offset = try uint(ph, if (bits == 64) 8 else 4, word);
        const vaddr = try uint(ph, if (bits == 64) 16 else 8, word);
        const size = try uint(ph, if (bits == 64) 32 else 16, word);
        if (address >= vaddr and address - vaddr < size) {
            const start = std.math.add(u64, offset, address - vaddr) catch return error.InvalidElf;
            return range(bytes, start, size - (address - vaddr));
        }
    }
    return error.InvalidElf;
}

fn range(bytes: []const u8, offset: u64, size: u64) ![]const u8 {
    if (offset > bytes.len or size > bytes.len - offset) return error.InvalidElf;
    return bytes[@intCast(offset)..@intCast(offset + size)];
}

fn uint(bytes: []const u8, offset: u64, size: usize) !u64 {
    const data = try range(bytes, offset, size);
    var result: u64 = 0;
    for (data, 0..) |byte, i| result |= @as(u64, byte) << @intCast(i * 8);
    return result;
}

fn cstring(table: []const u8, offset: u64) ![]const u8 {
    if (offset >= table.len) return error.InvalidElf;
    const data = table[@intCast(offset)..];
    const end = std.mem.indexOfScalar(u8, data, 0) orelse return error.InvalidElf;
    if (end == 0) return error.InvalidElf;
    return data[0..end];
}

test "ELF reader rejects truncated and overflowing program tables" {
    var bytes: [64]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u64, bytes[32..40], std.math.maxInt(u64), .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    try std.testing.expectError(error.InvalidElf, parse(std.testing.allocator, &bytes));
}
