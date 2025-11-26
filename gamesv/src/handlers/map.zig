const std = @import("std");
const pb = @import("proto").pb;
const network = @import("../network.zig");

pub fn onGetAreaMapDataCsReq(context: *network.Context, _: pb.GetAreaMapDataCsReq) !void {
    errdefer context.respond(pb.GetAreaMapDataScRsp{ .retcode = 1 }) catch {};
    const assets = context.connection.assets;

    const map_group_templates = assets.templates.urban_area_map_group_template_tb.payload.data;
    const group = try context.arena.alloc(pb.AreaGroupInfo, map_group_templates.len);
    for (map_group_templates, 0..) |template, i| {
        group[i] = .{
            .group_id = template.area_group_id,
            .area_progress = 99,
            .is_unlocked = true,
        };
    }

    const map_templates = assets.templates.urban_area_map_template_tb.payload.data;
    const street = try context.arena.alloc(pb.AreaStreetInfo, map_templates.len);
    for (map_templates, 0..) |template, i| {
        street[i] = .{
            .area_id = template.area_id,
            .area_progress = 99,
            .is_unlocked = true,
            .is_area_pop_show = true,
            .is_urban_area_show = true,
            .is_3d_area_show = true,
        };
    }

    try context.respond(pb.GetAreaMapDataScRsp{ .data = .{
        .group = group,
        .street = street,
    } });
}

pub fn onGetNewAreaPortalListCsReq(context: *network.Context, _: pb.GetNewAreaPortalListCsReq) !void {
    try context.respond(pb.GetNewAreaPortalListScRsp{ .retcode = 0 });
}
