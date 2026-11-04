"""Operating-system artefacts."""

type("system", parents = ["bytes"], abstract = True, description = "Operating-system artefacts")

type("system.evtx", parents = ["system"], mime = "application/octet-stream", ext = ["evt", "evtx"], description = "Windows event log")
type("system.lnk", parents = ["system"], mime = "application/x-ms-shortcut", ext = ["lnk"], description = "Windows shortcut")
type("system.minidump", parents = ["system"], mime = "application/octet-stream", ext = ["dmp"], description = "Windows crash dump")
type("system.prefetch", parents = ["system"], mime = "application/x-pf", ext = ["pf"], description = "Windows prefetch file")
type("system.pwl", parents = ["system"], mime = "application/octet-stream", ext = ["pwl"], description = "Windows password list")
type("system.registry-hbin", parents = ["system"], mime = "application/octet-stream", ext = ["hbin"], description = "Windows registry hive bin")
type("system.registry-hive", parents = ["system"], mime = "application/octet-stream", ext = ["registry"], description = "Windows registry hive")
type("system.registry-script", parents = ["system", "text"], mime = "application/octet-stream", ext = ["rgs"], description = "ATL registrar script")
type("system.task-job", parents = ["system"], mime = "application/octet-stream", ext = ["job"], description = "Windows Task Scheduler job")
