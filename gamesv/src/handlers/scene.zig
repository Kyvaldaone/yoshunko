const std = @import("std");
const pb = @import("proto").pb;
const network = @import("../network.zig");
const Player = @import("../fs/Player.zig");
const Hall = @import("../fs/Hall.zig");

pub fn onEnterWorldCsReq(context: *network.Context, _: pb.EnterWorldCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.EnterWorldScRsp{ .retcode = retcode }) catch {};
    defer if (retcode == 0) context.connection.flushSync(context.arena, context.io) catch {};

    const player = try context.connection.getPlayer();
    try switchSection(context, player);

    retcode = 0;
}

pub fn onEnterSectionCompleteCsReq(context: *network.Context, _: pb.EnterSectionCompleteCsReq) !void {
    try context.respond(pb.EnterSectionCompleteScRsp{});
}

pub fn onLeaveCurSceneCsReq(context: *network.Context, _: pb.LeaveCurSceneCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.LeaveCurSceneScRsp{ .retcode = retcode }) catch {};
    defer if (retcode == 0) context.connection.flushSync(context.arena, context.io) catch {};

    const player = try context.connection.getPlayer();
    try switchSection(context, player);

    retcode = 0;
}

pub fn onEnterSectionCsReq(context: *network.Context, request: pb.EnterSectionCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.EnterSectionScRsp{ .retcode = retcode }) catch {};
    defer if (retcode == 0) context.connection.flushSync(context.arena, context.io) catch {};

    const player = try context.connection.getPlayer();
    player.hall.section_id = request.section_id;

    try switchSection(context, player);
    const section = &player.cur_section.?;
    const new_position: Hall.Section.Position = .{
        .born_transform = try context.gpa.dupe(u8, request.transform_id),
    };

    section.position.deinit(context.gpa);
    section.position = new_position;

    retcode = 0;
}

pub fn onSavePosInMainCityCsReq(context: *network.Context, request: pb.SavePosInMainCityCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.SavePosInMainCityScRsp{ .retcode = retcode }) catch {};

    const player = try context.connection.getPlayer();
    const section = &(player.cur_section orelse return error.NotInHallSection);

    if (request.real_save and player.hall.section_id == request.section_id) {
        const transform = try Hall.Transform.fromProto(request.position orelse return error.NoPositionSpecified);

        section.position.deinit(context.gpa);
        section.position = .{ .custom = transform };
        player.sync.save_pos_in_main_city = true;
    }

    retcode = 0;
}

fn switchSection(context: *network.Context, player: *Player) !void {
    const log = std.log.scoped(.section_switch);

    player.performHallTransition(context.gpa, context.fs, context.connection.assets) catch |err| switch (err) {
        error.InvalidSectionID => {
            log.err(
                "section id {} is invalid, falling back to default section ({})",
                .{ player.hall.section_id, Hall.default_section_id },
            );
            player.hall.section_id = Hall.default_section_id;
            try player.performHallTransition(context.gpa, context.fs, context.connection.assets);
        },
        else => return err,
    };
}

pub fn onInteractWithUnitCsReq(context: *network.Context, request: pb.InteractWithUnitCsReq) !void {
    var retcode: i32 = 1;
    defer context.respond(pb.InteractWithUnitScRsp{ .retcode = retcode }) catch {};
    defer if (retcode == 0) context.connection.flushSync(context.arena, context.io) catch {};

    const player = try context.connection.getPlayer();
    try player.interactWithUnit(
        context.gpa,
        context.fs,
        context.connection.assets,
        @intCast(request.npc_tag_id),
        @intCast(request.interact_id),
    );

    retcode = 0;
}
