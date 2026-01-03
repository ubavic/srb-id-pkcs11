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
    const use_system_pkcs11 = b.option(bool, "use_system_pkcs11", "Use system PKCS11 headers") orelse false;
    const nss_include_path = b.option([]const u8, "nss_include_path", "NSS include path") orelse "/usr/include/nss";
    const nspr_include_path = b.option([]const u8, "nspr_include_path", "NSPR include path") orelse "/usr/include/nspr";

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/p11_general.zig"),
    });

    const pcsc_dep = b.dependency("pcsc", .{
        .target = target,
        .optimize = optimize,
        .link_system_pcsclite = (target.result.os.tag == .linux),
    });

    const pcsc_mod = pcsc_dep.module("pcsc");

    mod.addImport("pcsc", pcsc_mod);

    const lib = b.addLibrary(.{
        .linkage = std.builtin.LinkMode.dynamic,
        .name = "srb-id-pkcs11",
        .root_module = mod,
        .version = semver,
        .use_llvm = true,
        .use_lld = target.result.os.tag != .macos,
    });

    const lib_test = b.addTest(.{ .root_module = mod });

    lib.addIncludePath(b.path("include"));
    lib_test.addIncludePath(b.path("include"));

    if (use_system_pkcs11) {
        lib.addSystemIncludePath(.{ .cwd_relative = nss_include_path });
        lib.addSystemIncludePath(.{ .cwd_relative = nspr_include_path });
    } else {
        const header_file_step = checkPkcs11Headers(b);
        lib.step.dependOn(header_file_step);
        lib_test.step.dependOn(header_file_step);
    }

    b.installArtifact(lib);

    const lib_test_run = b.addRunArtifact(lib_test);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&lib_test_run.step);
}

fn checkPkcs11Headers(b: *std.Build) *std.Build.Step {
    const base_url = "https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/";
    const files = [3][]const u8{ "pkcs11.h", "pkcs11f.h", "pkcs11t.h" };

    const step = std.Build.step(b, "pkcs headers", "Download pkcs headers");
    inline for (files) |file_name| {
        _ = std.fs.cwd().openFile("include/" ++ file_name, .{ .mode = .read_only }) catch |e| {
            if (e == std.fs.File.OpenError.FileNotFound) {
                const curl_cmd = b.addSystemCommand(&.{"curl"});
                curl_cmd.addArg("-s");
                curl_cmd.addArg(base_url ++ file_name);
                const output = curl_cmd.captureStdOut();
                curl_cmd.expectExitCode(0);
                const inst_step = b.addInstallFileWithDir(output, .{ .custom = "../include" }, file_name);
                step.dependOn(&inst_step.step);
            }
        };
    }
    return step;
}
