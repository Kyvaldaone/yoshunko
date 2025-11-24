const std = @import("std");
const pb = @import("proto").pb;
const Player = @import("../fs/Player.zig");
const network = @import("../network.zig");
const property_util = @import("../logic/property_util.zig");

pub fn onStartTrainingQuestCsReq(context: *network.Context, request: pb.StartTrainingQuestCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.StartTrainingQuestScRsp{ .retcode = retcode }) catch {};

    const dungeon_package_info = try makeDungeonPackage(context, &.{request.avatar_id_list});

    try context.notify(pb.EnterSceneScNotify{
        .scene = .{
            .scene_type = 3,
            .scene_id = 19800014,
            .play_type = 290,
            .fight_scene_data = .{
                .scene_reward = .{},
                .scene_perform = .{},
            },
        },
        .dungeon = .{
            .quest_id = 12254000,
            .dungeon_package_info = dungeon_package_info,
        },
    });

    retcode = 0;
}

const hadal_static_zone_group: u32 = 61;
const hadal_periodic_zone_group: u32 = 62;
const hadal_periodic_zone_id: u32 = 62001;
const hadal_periodic_with_rooms_zone_id: u32 = 62010;
const hadal_zone_bosschallenge_zone_id: u32 = 69001;
const hadal_zone_alivecount_zone_id: u32 = 61002;
const hadal_zone_bosschallenge_zone_group: u32 = 69;
const hadal_zone_enemy_property_scale: u32 = 19;
const hadal_zone_bosschallenge_enemy_property_scale: u32 = 33;
const hadal_zone_impact_battle_enemy_property_scale: u32 = 61;

pub fn onStartHadalZoneBattleCsReq(context: *network.Context, request: pb.StartHadalZoneBattleCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.StartHadalZoneBattleScRsp{ .retcode = retcode }) catch {};

    const avatar_vec: []const []const u32 = &.{
        request.first_room_avatar_id_list,
        request.second_room_avatar_id_list,
    };

    var dungeon: pb.DungeonInfo = .{
        .dungeon_package_info = try makeDungeonPackage(context, avatar_vec),
        .avatar_list = try makeAvatarUnitList(context, avatar_vec),
    };

    var zone_group = request.zone_id;
    while ((zone_group / 100) > 0) zone_group /= 10;

    const layer_id: u32 = switch (zone_group) {
        hadal_static_zone_group => (request.zone_id * 100) + request.layer_index,
        hadal_periodic_zone_group => switch (request.room_index) {
            0 => (hadal_periodic_zone_id * 100) + request.layer_index,
            else => (hadal_periodic_with_rooms_zone_id * 100) + (request.layer_index * 10) + request.room_index,
        },
        hadal_zone_bosschallenge_zone_group => hadal_zone_bosschallenge_zone_id * 100 + request.layer_index,
        else => return error.InvalidZoneID,
    };

    const assets = context.connection.assets;
    const hadal_zone_quest_template = assets.templates.getConfigByKey(.hadal_zone_quest_template_tb, layer_id) orelse return error.MissingQuestForLayer;
    const quest_config_template = assets.templates.getConfigByKey(.quest_config_template_tb, hadal_zone_quest_template.quest_id) orelse return error.MissingQuestForLayer;

    dungeon.quest_type = quest_config_template.quest_type;
    dungeon.quest_id = @intCast(hadal_zone_quest_template.quest_id);

    const play_type = getHadalZonePlayType(request.zone_id, request.room_index);
    try context.notify(pb.EnterSceneScNotify{
        .scene = .{
            .scene_type = 9,
            .scene_id = layer_id,
            .play_type = @intFromEnum(play_type),
            .enemy_property_scale = switch (play_type) {
                .hadal_zone_bosschallenge => hadal_zone_bosschallenge_enemy_property_scale,
                .hadal_zone_impact_battle => hadal_zone_impact_battle_enemy_property_scale,
                else => hadal_zone_enemy_property_scale,
            },
            .hadal_zone_scene_data = .{
                .scene_perform = .{},
                .zone_id = request.zone_id,
                .layer_index = request.layer_index,
                .room_index = request.room_index,
                .layer_item_id = request.layer_item_id,
                .first_room_avatar_id_list = request.first_room_avatar_id_list,
                .second_room_avatar_id_list = request.second_room_avatar_id_list,
            },
        },
        .dungeon = dungeon,
    });

    retcode = 0;
}

fn getHadalZonePlayType(zone_id: u32, room_index: u32) LocalPlayType {
    if (zone_id == hadal_zone_alivecount_zone_id) return .hadal_zone_alivecount;

    var zone_group = zone_id;
    while ((zone_group / 100) > 0) zone_group /= 10;

    if (zone_group == hadal_zone_bosschallenge_zone_group) return .hadal_zone_bosschallenge;

    return switch (room_index) {
        0 => .hadal_zone,
        else => .hadal_zone_impact_battle,
    };
}

fn makeDungeonPackage(context: *network.Context, avatar_vec: []const []const u32) !pb.DungeonPackageInfo {
    const player = try context.connection.getPlayer();

    var avatar_list = try context.arena.alloc(pb.AvatarInfo, vecLen(avatar_vec));
    var weapon_list: std.ArrayList(pb.WeaponInfo) = .empty;
    var equip_list: std.ArrayList(pb.EquipInfo) = .empty;

    var i: usize = 0;
    for (avatar_vec) |list| {
        for (list) |avatar_id| {
            const avatar = player.avatar_map.getPtr(avatar_id) orelse return error.NoSuchAvatar;
            avatar_list[i] = try avatar.toProto(avatar_id, context.arena);

            if (avatar.cur_weapon_uid != 0) {
                if (player.weapon_map.getPtr(avatar.cur_weapon_uid)) |weapon| {
                    try weapon_list.append(context.arena, try weapon.toProto(avatar.cur_weapon_uid, context.arena));
                }
            }

            for (avatar.dressed_equip) |maybe_uid| {
                const uid = maybe_uid orelse continue;
                if (player.equip_map.getPtr(uid)) |equip| {
                    try equip_list.append(context.arena, try equip.toProto(uid, context.arena));
                }
            }

            i += 1;
        }
    }

    return .{
        .avatar_list = avatar_list,
        .weapon_list = weapon_list.items,
        .equip_list = equip_list.items,
    };
}

pub fn makeAvatarUnitList(
    context: *network.Context,
    avatar_vec: []const []const u32,
) ![]const pb.AvatarUnitInfo {
    const player = try context.connection.getPlayer();

    var unit_list = try context.arena.alloc(pb.AvatarUnitInfo, vecLen(avatar_vec));
    var i: usize = 0;

    for (avatar_vec) |list| {
        for (list) |avatar_id| {
            const property_map = try property_util.makePropertyMap(
                player,
                context.arena,
                context.connection.assets,
                avatar_id,
            );

            const properties = try context.arena.alloc(pb.MapEntry(u32, i32), property_map.count());

            var iterator = property_map.iterator();
            var j: usize = 0;
            while (iterator.next()) |kv| : (j += 1) {
                properties[j] = .{
                    .key = @intFromEnum(kv.key_ptr.*),
                    .value = kv.value_ptr.*,
                };
            }

            unit_list[i] = .{
                .avatar_id = avatar_id,
                .properties = properties,
            };

            i += 1;
        }
    }

    return unit_list;
}

fn vecLen(vec: anytype) usize {
    var len: usize = 0;
    for (vec) |list| len += list.len;

    return len;
}

pub fn onEndBattleCsReq(context: *network.Context, _: pb.EndBattleCsReq) !void {
    try context.respond(pb.EndBattleScRsp{
        .retcode = 0,
        .fight_settle = .{},
    });
}

pub const LocalPlayType = enum(u32) {
    unkown = 0,
    archive_battle = 201,
    chess_board_battle = 202,
    guide_special = 203,
    chess_board_longfihgt_battle = 204,
    level_zero = 205,
    daily_challenge = 206,
    rally_long_fight = 207,
    dual_elite = 208,
    hadal_zone = 209,
    boss_battle = 210,
    big_boss_battle = 211,
    archive_long_fight = 212,
    avatar_demo_trial = 213,
    mp_big_boss_battle = 214,
    boss_little_battle_longfight = 215,
    operation_beta_demo = 216,
    big_boss_battle_longfight = 217,
    boss_rush_battle = 218,
    operation_team_coop = 219,
    boss_nest_hard_battle = 220,
    side_scrolling_thegun_battle = 221,
    hadal_zone_alivecount = 222,
    babel_tower = 223,
    hadal_zone_bosschallenge = 224,
    s2_rogue_battle = 226,
    buddy_towerdefense_battle = 227,
    mini_scape_battle = 228,
    mini_scape_short_battle = 229,
    activity_combat_pause = 230,
    coin_brushing_battle = 231,
    turn_based_battle = 232,
    bangboo_royale = 240,
    side_scrolling_captain = 241,
    smash_bro = 242,
    pure_hollow_battle = 280,
    pure_hollow_battle_longhfight = 281,
    pure_hollow_battle_hardmode = 282,
    training_room = 290,
    map_challenge_battle = 291,
    training_root_tactics = 292,
    bangboo_dream_rogue_battle = 293,
    target_shooting_battle = 294,
    bangboo_autobattle = 295,
    mechboo_battle = 296,
    summer_surfing = 297,
    summer_shooting = 298,
    void_front_battle_boss = 299,
    void_front_battle = 300,
    void_front_buff_battle = 301,
    activity_combat_pause_annihilate = 302,
    hadal_zone_impact_battle = 303,
    mechboo_battlev2 = 304,
    operation_team_coop_stylish = 305,
};
