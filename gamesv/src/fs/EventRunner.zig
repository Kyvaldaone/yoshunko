const EventRunner = @This();
const std = @import("std");
const proto = @import("proto");
const pb = proto.pb;
const common = @import("common");
const file_util = @import("file_util.zig");
const Assets = @import("../data/Assets.zig");

const Player = @import("Player.zig");
const Hall = @import("Hall.zig");

const Allocator = std.mem.Allocator;
const FileSystem = common.FileSystem;
const EventConfig = Assets.EventGraphCollection.EventConfig;

const log = std.log.scoped(.event_runner);

pub fn runEvent(player: *Player, gpa: Allocator, fs: *FileSystem, assets: *const Assets, event: *const EventConfig) !void {
    var temp_allocator = std.heap.ArenaAllocator.init(gpa);
    defer temp_allocator.deinit();
    const arena = temp_allocator.allocator();

    for (event.actions) |action| {
        switch (action.action) {
            .create_npc => |config| {
                try handleCreateNpc(player, gpa, arena, fs, assets, config);
            },
            .change_interact => |config| {
                try handleChangeInteract(player, gpa, arena, fs, assets, config);
            },
            else => {},
        }

        switch (action.action) {
            inline else => |config| {
                if (@hasDecl(@TypeOf(config), "toProto")) {
                    try addClientEvent(player, gpa, action.id, @enumFromInt(@intFromEnum(action.action)), config);
                }
            },
        }
    }
}

fn handleCreateNpc(
    player: *Player,
    gpa: Allocator,
    arena: Allocator,
    fs: *FileSystem,
    assets: *const Assets,
    config: anytype,
) !void {
    const template = assets.templates.getConfigByKey(.main_city_object_template_tb, config.tag_id) orelse {
        log.err("missing config for npc with tag {}", .{config.tag_id});
        return;
    };

    var npc: Hall.Npc = .{};

    if (template.default_interact_ids.len != 0) {
        npc.interacts[1] = .{
            .name = try gpa.dupe(u8, template.interact_name),
            .scale = @splat(1),
            .tag_id = config.tag_id,
            .id = template.default_interact_ids[0],
        };
    }

    try saveNpc(arena, fs, player.player_uid, player.hall.section_id, config.tag_id, npc);
    try player.active_npcs.put(gpa, config.tag_id, npc);
}

fn handleChangeInteract(
    player: *Player,
    gpa: Allocator,
    arena: Allocator,
    fs: *FileSystem,
    assets: *const Assets,
    config: anytype,
) !void {
    for (config.tag_ids) |tag_id| {
        const npc = player.active_npcs.getPtr(tag_id) orelse continue;
        const template = assets.templates.getConfigByKey(.main_city_object_template_tb, tag_id) orelse {
            log.err("missing config for npc with tag {}", .{tag_id});
            continue;
        };

        if (npc.interacts[1]) |*interact| interact.deinit(gpa);

        const participators = try gpa.alloc(Hall.Interact.Participator, 1);
        participators[0] = .{ .id = 102201, .name = try gpa.dupe(u8, "A") };
        npc.interacts[1] = .{
            .name = try gpa.dupe(u8, template.interact_name),
            .scale = @splat(1),
            .tag_id = tag_id,
            .participators = participators,
            .id = config.interact_id,
        };

        try saveNpc(arena, fs, player.player_uid, player.hall.section_id, tag_id, npc.*);
    }
}

fn addClientEvent(player: *Player, gpa: Allocator, action_id: u32, action_type: pb.ActionType, config: anytype) !void {
    var client_event = Player.Sync.ClientEvent.init(gpa);
    errdefer client_event.deinit();

    try client_event.add(action_id, action_type, config);
    try player.sync.client_events.append(gpa, client_event);
}

fn saveNpc(arena: Allocator, fs: *FileSystem, player_uid: u32, section_id: u32, npc_id: u32, npc: Hall.Npc) !void {
    const npc_zon = try file_util.serializeZon(arena, npc);
    const npc_path = try std.fmt.allocPrint(
        arena,
        "player/{}/hall/{}/{}",
        .{ player_uid, section_id, npc_id },
    );
    try fs.writeFile(npc_path, npc_zon);
}