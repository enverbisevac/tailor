const std = @import("std");

pub const Call = struct { command: ?[]const u8, offset: usize, api: []const u8 };

/// Conservative syntactic discovery for common direct process APIs. It does
/// not claim whole-program reachability or resolve aliases/reflection.
pub fn scan(allocator: std.mem.Allocator, source: []const u8) ![]Call {
    var calls: std.ArrayList(Call) = .empty;
    errdefer calls.deinit(allocator);
    const apis = [_][]const u8{ "exec.Command", "exec.CommandContext", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "ProcessBuilder", "Runtime.getRuntime().exec", "child_process.spawn", "child_process.execFile", "spawn", "execFile" };
    var pos: usize = 0;
    while (pos < source.len) {
        // Skip comments and string contents so documentation is not treated as
        // executed code. Template strings remain unresolved at call sites.
        if (source[pos] == '#' or std.mem.startsWith(u8, source[pos..], "//")) {
            pos = (std.mem.indexOfScalarPos(u8, source, pos, '\n') orelse source.len);
            continue;
        }
        if (std.mem.startsWith(u8, source[pos..], "/*")) {
            pos = if (std.mem.indexOfPos(u8, source, pos + 2, "*/")) |end| end + 2 else source.len;
            continue;
        }
        if (source[pos] == '\'' or source[pos] == '"' or source[pos] == '`') {
            pos = quotedEnd(source, pos) orelse source.len;
            continue;
        }
        var matched = false;
        for (apis) |api| {
            if (!std.mem.startsWith(u8, source[pos..], api)) continue;
            if (pos > 0 and (std.ascii.isAlphanumeric(source[pos - 1]) or source[pos - 1] == '_')) continue;
            var cursor = skipSpace(source, pos + api.len);
            if (cursor >= source.len or source[cursor] != '(') continue;
            cursor = skipSpace(source, cursor + 1);
            if (std.mem.eql(u8, api, "exec.CommandContext")) {
                cursor = (std.mem.indexOfScalarPos(u8, source, cursor, ',') orelse source.len);
                cursor = skipSpace(source, @min(cursor + 1, source.len));
            }
            if (cursor < source.len and (source[cursor] == '[' or source[cursor] == '(')) cursor = skipSpace(source, cursor + 1);
            var command: ?[]const u8 = null;
            if (cursor < source.len and (source[cursor] == '\'' or source[cursor] == '"')) {
                if (quotedEnd(source, cursor)) |end| {
                    const literal = source[cursor + 1 .. end - 1];
                    const following = skipSpace(source, end);
                    // Concatenation/interpolation is not a literal command.
                    if (following < source.len and std.mem.indexOfScalar(u8, ",)]", source[following]) != null and safeName(literal)) command = literal;
                }
            }
            try calls.append(allocator, .{ .command = command, .offset = pos, .api = api });
            pos += api.len;
            matched = true;
            break;
        }
        if (!matched) pos += 1;
    }
    return calls.toOwnedSlice(allocator);
}

fn safeName(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '-')) return false;
    return true;
}

fn skipSpace(source: []const u8, start: usize) usize {
    var pos = start;
    while (pos < source.len and std.ascii.isWhitespace(source[pos])) : (pos += 1) {}
    return pos;
}

fn quotedEnd(source: []const u8, start: usize) ?usize {
    var pos = start + 1;
    while (pos < source.len) : (pos += 1) {
        if (source[pos] == '\\') {
            pos += 1;
            continue;
        }
        if (source[pos] == source[start]) return pos + 1;
    }
    return null;
}

test "direct process calls across languages discover literals and flag dynamic commands" {
    const source =
        \\exec.Command("git", "status")
        \\subprocess.run(["git", "status"])
        \\new ProcessBuilder("git", "status")
        \\child_process.spawn("git", ["status"])
        \\exec.Command(command)
        \\spawn("gi" + suffix)
        \\// exec.Command("ignored")
    ;
    const calls = try scan(std.testing.allocator, source);
    defer std.testing.allocator.free(calls);
    try std.testing.expectEqual(@as(usize, 6), calls.len);
    for (calls[0..4]) |call| try std.testing.expectEqualStrings("git", call.command.?);
    try std.testing.expect(calls[4].command == null);
    try std.testing.expect(calls[5].command == null);
}
