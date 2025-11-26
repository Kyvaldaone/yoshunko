const Hall = @This();
const std = @import("std");
const pb = @import("proto").pb;
const templates = @import("../data/templates.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const default_section_id: u32 = 1;

pub const default: @This() = .{};
section_id: u32 = default_section_id,
time_in_minutes: u11 = 360,
day_of_week: u3 = 5,

pub fn deinit(hall: Hall, gpa: Allocator) void {
    std.zon.parse.free(gpa, hall);
}

pub const Transform = struct {
    position: [3]f64,
    rotation: [3]f64,

    pub fn toProto(t: Transform, arena: Allocator) !pb.Transform {
        return .{
            .position = try arena.dupe(f64, t.position[0..]),
            .rotation = try arena.dupe(f64, t.rotation[0..]),
        };
    }

    pub fn fromProto(t: pb.Transform) !Transform {
        if (t.position.len != 3 or t.rotation.len != 3) return error.IllFormedTransform;

        var result: Transform = undefined;
        @memcpy(result.position[0..], t.position);
        @memcpy(result.rotation[0..], t.rotation);

        return result;
    }
};

pub const Section = struct {
    position: Position,

    pub const Position = union(enum) {
        born_transform: []const u8,
        custom: Transform,

        pub fn deinit(position: Position, gpa: Allocator) void {
            switch (position) {
                .born_transform => |bt| gpa.free(bt),
                .custom => {},
            }
        }
    };

    pub fn createDefault(gpa: Allocator, template: *const templates.SectionConfigTemplate) !@This() {
        return .{ .position = .{
            .born_transform = try gpa.dupe(u8, template.default_transform),
        } };
    }

    pub fn deinit(section: Section, gpa: Allocator) void {
        std.zon.parse.free(gpa, section);
    }
};

pub const Npc = struct {
    interacts: [2]?Interact = @splat(null),

    pub fn deinit(npc: Npc, gpa: Allocator) void {
        std.zon.parse.free(gpa, npc);
    }

    pub fn toProto(npc: Npc, arena: Allocator, id: u32) !pb.NpcInfo {
        var info: pb.NpcInfo = .{
            .npc_id = id,
            .is_active = true,
        };

        var interacts: usize = 0;
        for (npc.interacts) |maybe_interact| if (maybe_interact != null) {
            interacts += 1;
        };

        var interacts_info = try arena.alloc(pb.MapEntry(u32, pb.InteractInfo), interacts);
        var j: usize = 0;
        for (npc.interacts, 0..) |maybe_interact, i| {
            const interact = maybe_interact orelse continue;
            var interact_info: pb.InteractInfo = .{
                .tag_id = @intCast(interact.tag_id),
                .scale_x = interact.scale[0],
                .scale_y = interact.scale[1],
                .scale_z = interact.scale[2],
                .scale_w = interact.scale[3],
                .scale_r = interact.scale[4],
                .interact_target_list = try arena.dupe(pb.InteractTarget, &.{switch (i) {
                    0 => .trigger_box,
                    1 => .npc,
                    else => unreachable,
                }}),
                .name = try arena.dupe(u8, interact.name),
            };

            var participators = try arena.alloc(pb.MapEntry(u32, []const u8), interact.participators.len);
            for (interact.participators, 0..) |participator, k| {
                participators[k] = .{
                    .key = participator.id,
                    .value = try arena.dupe(u8, participator.name),
                };
            }

            interact_info.participators = participators;
            interacts_info[j] = .{ .key = interact.id, .value = interact_info };
            j += 1;
        }

        info.interacts_info = interacts_info;
        return info;
    }
};

pub const Interact = struct {
    pub const Participator = struct { id: u32, name: []const u8 };

    id: u32,
    tag_id: u32,
    participators: []Participator = &.{},
    name: []const u8,
    scale: [5]f64,

    pub fn deinit(interact: *Interact, gpa: Allocator) void {
        gpa.free(interact.name);
        gpa.free(interact.participators);
    }
};
