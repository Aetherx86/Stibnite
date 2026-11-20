const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Native executable harness
    const exe = b.addExecutable(.{
        .name = "stibnite",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    // C-ABI Interposition Shared Library
    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "stibnite",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/interceptor.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    lib.installHeader(b.path("include/stibnite.h"), "stibnite.h");
    b.installArtifact(lib);

    // Test runner (main.zig pulls in every module's tests)
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests and the C-ABI test");
    test_step.dependOn(&run_unit_tests.step);

    // C program linked against the shared library through include/stibnite.h
    const abi_test = b.addExecutable(.{
        .name = "abi_test",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    abi_test.root_module.addCSourceFile(.{ .file = b.path("tests/abi_test.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror", "-D_DEFAULT_SOURCE" } });
    abi_test.root_module.addIncludePath(b.path("include"));
    abi_test.root_module.linkLibrary(lib);
    const run_abi_test = b.addRunArtifact(abi_test);
    run_abi_test.expectExitCode(0);
    test_step.dependOn(&run_abi_test.step);
}
