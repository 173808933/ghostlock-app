import java.util.Properties

plugins {
    id("com.android.application") version "9.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
    id("org.jetbrains.kotlin.jvm") version "2.4.20" apply false
}

private fun localProperties(): Properties = Properties().also { properties ->
    val propertiesFile = rootProject.file("local.properties")
    if (propertiesFile.isFile) {
        propertiesFile.inputStream().use(properties::load)
    }
}

private fun ondkHome(): String? =
    System.getenv("ONDK_HOME")?.takeIf(String::isNotBlank)
        ?: localProperties().getProperty("ondk.dir")?.takeIf(String::isNotBlank)

private fun useOndk(): Boolean = !ondkHome().isNullOrBlank()

private fun resolveNdkDir(): String {
    val ondk = ondkHome()
    if (ondk != null) return ondk

    val properties = localProperties()
    val ndkEnvironment = System.getenv("ANDROID_NDK_HOME")
        ?: System.getenv("ANDROID_NDK_ROOT")
    if (!ndkEnvironment.isNullOrBlank()) return ndkEnvironment

    properties.getProperty("ndk.dir")?.takeIf(String::isNotBlank)?.let { return it }

    val sdkDir = properties.getProperty("sdk.dir") ?: System.getenv("ANDROID_HOME")
    if (!sdkDir.isNullOrBlank()) {
        val ndkRoot = File(sdkDir, "ndk")
        val versions = ndkRoot.listFiles()
            ?.filter(File::isDirectory)
            ?.map(File::getName)
            ?.sorted()
            .orEmpty()
        if (versions.isNotEmpty()) return File(ndkRoot, versions.last()).absolutePath
    }

    throw GradleException("NDK not found; set ANDROID_NDK_HOME or ndk.dir in local.properties")
}

private data class NdkTools(val clang: String, val ar: String)

/* The rustup proxy, not a concrete toolchain binary: `cargo +ondk build` is a
 * proxy-side argument and a real cargo from ~/.rustup/toolchains/<triple>/bin
 * rejects it ("no such command: +ondk"). ONDK builds must go through this path. */
private fun resolveRustupCargo(): String {
    val names = if (System.getProperty("os.name").lowercase().contains("windows")) {
        listOf("cargo.exe", "cargo")
    } else {
        listOf("cargo")
    }
    val onPath = System.getenv("PATH")
        .orEmpty()
        .split(File.pathSeparator)
        .asSequence()
        .flatMap { dir -> names.asSequence().map { File(dir, it) } }
        .firstOrNull { it.isFile && it.canExecute() }
    if (onPath != null) return onPath.absolutePath

    val inRustupHome = names.asSequence()
        .map { File(File(System.getProperty("user.home"), ".cargo/bin"), it) }
        .firstOrNull { it.isFile && it.canExecute() }
    return inRustupHome?.absolutePath ?: "cargo"
}

private fun resolveCargoExecutable(): String {
    /* Windows installs cargo.exe; File("...", "cargo") never matches there, so
     * probe both spellings and prefer an absolute path (the bare "cargo"
     * fallback relies on CreateProcess PATH search, which fails when the JVM
     * inherits an MSYS-style PATH from Git Bash). */
    val isWindows = System.getProperty("os.name").lowercase().contains("windows")
    val names = if (isWindows) listOf("cargo.exe", "cargo") else listOf("cargo")

    /* Real toolchains before anything else: the ~/.cargo/bin shims are rustup
     * proxies, and a proxy whose metadata is out of sync fails with
     * "not a valid application for this OS platform" even though the toolchain
     * itself works. The std manifest check keeps a half-installed toolchain
     * from being picked. */
    val toolchains = File(System.getProperty("user.home"), ".rustup/toolchains")
    val realToolchain = toolchains.listFiles()
        .orEmpty()
        .filter { it.isDirectory }
        .sortedByDescending { it.name }
        .asSequence()
        .mapNotNull { dir -> names.asSequence().map { File(dir, "bin/$it") }.firstOrNull { it.isFile } }
        .firstOrNull { cargo ->
            val root = cargo.parentFile.parentFile
            File(root, "lib/rustlib").listFiles().orEmpty()
                .any { it.name.startsWith("manifest-rust-std-") }
        }
    if (realToolchain != null) return realToolchain.absolutePath

    val onPath = System.getenv("PATH")
        .orEmpty()
        .split(File.pathSeparator)
        .asSequence()
        .flatMap { dir -> names.asSequence().map { File(dir, it) } }
        .firstOrNull { it.isFile && it.canExecute() }
    if (onPath != null) return onPath.absolutePath

    val rustupHome = File(System.getProperty("user.home"), ".cargo/bin")
    val inRustupHome = names.asSequence()
        .map { File(rustupHome, it) }
        .firstOrNull { it.isFile && it.canExecute() }
    return inRustupHome?.absolutePath ?: "cargo"
}

private fun extractNdkTools(): NdkTools {
    val ndk = resolveNdkDir()
    val osName = System.getProperty("os.name").lowercase()
    val isWindows = osName.contains("windows")
    val prebuilt = when {
        isWindows -> "windows-x86_64"
        osName.contains("mac") -> "darwin-x86_64"
        else -> "linux-x86_64"
    }
    val binDir = File(ndk, "toolchains/llvm/prebuilt/$prebuilt/bin")
    return NdkTools(
        clang = File(
            binDir,
            if (isWindows) "aarch64-linux-android34-clang.cmd" else "aarch64-linux-android34-clang",
        ).absolutePath,
        ar = File(binDir, if (isWindows) "llvm-ar.exe" else "llvm-ar").absolutePath,
    )
}

// Every module's output lives under the root build/ directory (native,
// host-test, extract, kernel-profiles, app). Delete the whole tree here so a
// single root `clean` resets all of them.
tasks.register<Delete>("clean") {
    description = "Delete the root build/ directory (all module outputs)."
    delete(layout.buildDirectory)
}

tasks.register<Exec>("buildGhostlockNative") {
    description = "buildGhostlockNative"
    workingDir(file("src"))
    commandLine("make", "ghostlock")
    val ndk = resolveNdkDir()
    environment("ANDROID_NDK_HOME", ndk)
    environment("NDK_ROOT", ndk)
    inputs.files(
        fileTree("src") { include("**/*.c", "**/*.h", "**/*.cpp", "**/*.hpp") },
        file("src/Makefile"),
    )
    outputs.file(file("build/native/ghostlock"))
}

tasks.register<Copy>("prepareGhostlockJniLibs") {
    description = "prepareGhostlockJniLibs"
    dependsOn("buildGhostlockNative")
    from("build/native/ghostlock")
    into("app/src/main/jniLibs/arm64-v8a")
    rename { "libghostlock.so" }
    /* Strip only the packaged copy: static libc++ carries its DWARF into the
     * binary, while the top-level ghostlock keeps its symbols for the
     * disassembly comparisons. Paths are captured as plain strings so the
     * configuration cache can serialize this task. */
    val stripPath = File(extractNdkTools().clang)
        .resolveSibling("llvm-strip").absolutePath
    val packagedPath = File(rootDir, "app/src/main/jniLibs/arm64-v8a/libghostlock.so").absolutePath
    doLast {
        val code = ProcessBuilder(stripPath, "--strip-all", packagedPath)
            .inheritIO()
            .start()
            .waitFor()
        check(code == 0) { "llvm-strip failed with $code" }
    }
}

tasks.register<Exec>("buildGhostlockExtract") {
    description = "buildGhostlockExtract"
    val tools = extractNdkTools()
    val isOndk = useOndk()
    /* An ONDK build needs the rustup proxy so that +ondk resolves the linked
     * toolchain and -Z build-std is permitted; a local build wants the real
     * toolchain binary, because the shims on this machine are broken. */
    val cargoExecutable = if (isOndk) resolveRustupCargo() else resolveCargoExecutable()
    val command = mutableListOf(cargoExecutable)
    if (isOndk) command += "+ondk"
    command += listOf("build", "--release", "--target", "aarch64-linux-android")
    if (isOndk) {
        command += listOf("-Z", "build-std=std,panic_abort")
        command += listOf("-Z", "build-std-features=optimize_for_size")
    }
    workingDir(rootProject.file("tools/extract_rs"))
    commandLine(command)
    /* Pin rustc to the same toolchain as cargo. An inherited PATH may resolve
     * "rustc" to a rustup shim, and a shim whose metadata is off produces host
     * build scripts that die with os error 193 at run time. Skipped for ONDK:
     * there the rustup proxy owns toolchain selection, and pinning a concrete
     * rustc would fight `+ondk`. */
    val isWindowsHost = System.getProperty("os.name").lowercase().contains("windows")
    if (!isOndk) {
        environment(
            "RUSTC",
            File(cargoExecutable).resolveSibling(if (isWindowsHost) "rustc.exe" else "rustc").absolutePath,
        )
    }
    environment("CC_aarch64_linux_android", tools.clang)
    environment("AR_aarch64_linux_android", tools.ar)
    environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", tools.clang)
    /* Target-scoped, never the global RUSTFLAGS: the global form also reaches
     * the host build scripts, and "-C link-arg=-Wl,--icf=all" makes the MSVC
     * host linker emit a PE cargo then rejects with os error 193. */
    environment(
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS",
        "-C force-unwind-tables=no -C link-arg=-Wl,--icf=all",
    )
    if (isOndk) environment("RUSTC_BOOTSTRAP", "1")
    inputs.files(
        fileTree("tools/extract_rs/src") { include("**/*.rs") },
        file("tools/extract_rs/Cargo.toml"),
        file("tools/extract_rs/Cargo.lock"),
    )
    inputs.property("useOndk", isOndk)
    outputs.file(file("build/extract/aarch64-linux-android/release/ghostlock-extract"))
}

tasks.register<Copy>("prepareGhostlockExtractJniLibs") {
    description = "prepareGhostlockExtractJniLibs"
    dependsOn("buildGhostlockExtract")
    from("build/extract/aarch64-linux-android/release/ghostlock-extract")
    into("app/src/main/jniLibs/arm64-v8a")
    rename { "libextract.so" }
}
