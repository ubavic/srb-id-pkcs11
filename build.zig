const std = @import("std");

const version = @import("src/version.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const semver = std.SemanticVersion{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
    };

    const lib = b.addSharedLibrary(.{
        .name = "srb-id-pkcs11",
        .root_source_file = b.path("src/p11_general.zig"),
        .target = target,
        .optimize = optimize,
        .version = semver,
    });

    lib.addIncludePath(b.path("include"));
    lib.addIncludePath(.{ .cwd_relative = "/usr/include/PCSC/" });

    lib.linkSystemLibrary("pcsclite");

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/p11_general.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
