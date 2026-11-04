"""Disk and file-system images."""

type("disk", parents = ["bytes"], abstract = True, description = "Disk and file-system images")

type("disk.dmg", parents = ["disk"], mime = "application/x-apple-diskimage", ext = ["dmf", "dmg"], description = "Apple disk image")
type("disk.iso", parents = ["disk"], mime = "application/octet-stream", ext = ["iso"], description = "ISO 9660 image")
type("disk.vhd", parents = ["disk"], mime = "application/x-vhd", ext = ["vhd"], description = "Virtual hard disk")
type("disk.vmdk", parents = ["disk"], mime = "application/vmdk", ext = ["vmdk"], description = "VMware virtual disk")
