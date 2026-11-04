"""Executable code and object formats."""

type("executable", parents = ["bytes"], abstract = True, description = "Executable code and object formats")

type("executable.dos-mz", parents = ["executable"], mime = "application/x-dosexec", ext = ["exe", "com"], description = "DOS MZ executable (no PE header)")
type("executable.dotnet", parents = ["executable.pe"], description = ".NET (CLR) assembly")
type("executable.elf", parents = ["executable"], mime = "application/x-elf", ext = ["axf", "bin", "elf", "o", "prx", "so"], description = "ELF executable or object")
type("executable.elf-shared-object", parents = ["executable.elf"], mime = "application/x-sharedlib", ext = ["so"], description = "ELF shared library")
type("executable.java-class", parents = ["executable"], mime = "application/java-vm", ext = ["class"], description = "Java class file")
type("executable.lua-bytecode", parents = ["executable"], mime = "application/x-lua", ext = ["luac"], description = "Lua bytecode")
type("executable.macho", parents = ["executable"], mime = "application/x-mach-binary", ext = ["dylib", "bundle", "o"], description = "Mach-O binary")
type("executable.macho-universal", parents = ["executable"], mime = "application/octet-stream", ext = ["dylib"], description = "Universal (fat) Mach-O binary")
type("executable.msi", parents = ["executable", "document.ole2"], mime = "application/x-msi", ext = ["msi"], description = "Windows Installer package")
type("executable.pe", parents = ["executable"], mime = "application/vnd.microsoft.portable-executable", ext = ["com", "dll", "drv", "exe", "fon", "ocx", "scr", "sys", "vbx", "vxd"], description = "Windows Portable Executable")
type("executable.pe-dll", parents = ["executable.pe"], mime = "application/x-msdownload", ext = ["dll"], description = "Windows DLL")
type("executable.swf", parents = ["executable"], mime = "application/x-shockwave-flash", ext = ["swf"], description = "Adobe Flash (SWF)")
type("executable.wasm", parents = ["executable"], mime = "application/octet-stream", ext = ["wasm"], description = "WebAssembly module")
