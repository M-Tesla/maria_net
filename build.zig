const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addIncludePath(b.path("third_party/curl-8.18.0/include"));
    mod.addLibraryPath(b.path("third_party/lib"));
    mod.linkSystemLibrary("curl", .{});
    mod.linkSystemLibrary("mariadb", .{});
    mod.addCSourceFile(.{
        .file = b.path("src/curl_shim.c"),
        .flags = &.{ "-std=c11" },
    });
    const net_sql = b.createModule(.{
        .root_source_file = b.path("sql/embed.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("net_sql", net_sql);

    const exe = b.addExecutable(.{
        .name = "maria-net",
        .root_module = mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run maria-net");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests and delivery tests when MARIA_NET_TEST_HOST is set");
    test_step.dependOn(&run_tests.step);
}
