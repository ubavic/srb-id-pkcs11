const std = @import("std");

const version = @import("src/version.zig");

const semver = std.SemanticVersion{
    .major = version.major,
    .minor = version.minor,
    .patch = version.patch,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/p11_general.zig"),
    });

    const pcsc_dep = b.dependency("pcsc", .{ .target = target, .optimize = optimize });
    const pcsc_mod = pcsc_dep.module("pcsc");

    mod.addImport("pcsc", pcsc_mod);

    const lib = b.addLibrary(.{
        .linkage = std.builtin.LinkMode.dynamic,
        .name = "srb-id-pkcs11",
        .root_module = mod,
        .version = semver,
        .use_llvm = true,
        .use_lld = true,
    });

    const lib_test = b.addTest(.{ .root_module = mod });

    lib.addIncludePath(b.path("include"));
    lib_test.addIncludePath(b.path("include"));

    b.installArtifact(lib);

    const lib_test_run = b.addRunArtifact(lib_test);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&lib_test_run.step);
}
