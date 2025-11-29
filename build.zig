const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const common = b.createModule(.{
        .root_source_file = b.path("common/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const proto_gen = b.addExecutable(.{
        .name = "yoshunko-protogen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("proto/gen/src/main.zig"),
            .optimize = optimize,
            .target = target,
        }),
    });
    const update_src = b.addUpdateSourceFiles();
    if (std.fs.cwd().access("proto/pb/nap.proto", .{})) {
        const run_proto_gen = b.addRunArtifact(proto_gen);
        run_proto_gen.expectExitCode(0);
        run_proto_gen.setStdIn(.{ .lazy_path = b.path("proto/pb/nap.proto") });
        const pb_gen = run_proto_gen.captureStdOut(.{ .basename = "nap_generated.zig" });
        update_src.addCopyFileToSource(pb_gen, "proto/src/nap_generated.zig");
    } else |_| {}
    const proto = b.createModule(.{
        .root_source_file = b.path("proto/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const dpsv_exe = b.addExecutable(.{
        .name = "yoshunko-dpsv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("dpsv/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "common", .module = common }},
        }),
    });
    const gamesv_exe = b.addExecutable(.{
        .name = "yoshunko-gamesv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("gamesv/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "common", .module = common },
                .{ .name = "proto", .module = proto },
            },
        }),
    });
    b.step("run-dpsv", "run the dispatch server").dependOn(&b.addRunArtifact(dpsv_exe).step);
    const run_gamesv = b.addRunArtifact(gamesv_exe);
    run_gamesv.step.dependOn(&update_src.step);
    b.step("run-gamesv", "run the game server").dependOn(&run_gamesv.step);
    b.installArtifact(dpsv_exe);
    b.installArtifact(gamesv_exe);
}