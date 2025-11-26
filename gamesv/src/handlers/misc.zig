const std = @import("std");
const pb = @import("proto").pb;
const network = @import("../network.zig");

pub fn onGetMiscDataCsReq(context: *network.Context, _: pb.GetMiscDataCsReq) !void {
    errdefer context.respond(pb.GetMiscDataScRsp{ .retcode = 1 }) catch {};
    const player = try context.connection.getPlayer();
    const templates = context.connection.assets.templates;

    var data: pb.MiscData = .{
        .business_card = .{},
        .player_accessory = .{
            .control_guise_avatar_id = player.basic_info.control_guise_avatar_id,
        },
        .post_girl = .{
            .post_girl_item_list = &.{.{ .id = 3510041 }},
            .show_post_girl_id_list = &.{3510041},
        },
    };

    var unlocked_list = try context.arena.alloc(i32, templates.unlock_config_template_tb.payload.data.len);
    for (templates.unlock_config_template_tb.payload.data, 0..) |template, i| {
        unlocked_list[i] = @intCast(template.id);
    }
    data.unlock = .{ .unlocked_list = unlocked_list };

    var teleport_list = try context.arena.alloc(i32, templates.teleport_config_template_tb.payload.data.len);
    for (templates.teleport_config_template_tb.payload.data, 0..) |template, i| {
        teleport_list[i] = @intCast(template.teleport_id);
    }
    data.teleport = .{ .unlocked_list = teleport_list };

    try context.respond(pb.GetMiscDataScRsp{ .data = data });
}
