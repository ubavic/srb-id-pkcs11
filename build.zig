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

    switch (target.result.os.tag) {
        .windows => {
            lib.linkSystemLibrary("Winscard");
            lib_test.linkSystemLibrary("Winscard");
        },
        .linux => {
            lib.addIncludePath(.{ .cwd_relative = "/usr/include/PCSC/" });
            lib.linkSystemLibrary("pcsclite");
            lib_test.addIncludePath(.{ .cwd_relative = "/usr/include/PCSC/" });
            lib_test.linkSystemLibrary("pcsclite");
        },
        .macos => {
            lib.linkFramework("PCSC");
            lib_test.linkFramework("PCSC");
        },
        else => unreachable,
    }

    b.installArtifact(lib);

    const lib_test_run = b.addRunArtifact(lib_test);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&lib_test_run.step);
}
