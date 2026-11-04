"""Android application formats."""

type("android", parents = ["bytes"], abstract = True, description = "Android application formats")

type("android.aab", parents = ["archive.zip", "android"], mime = "application/octet-stream", ext = ["aab"], description = "Android App Bundle")
type("android.apk", parents = ["archive.zip", "android"], mime = "application/vnd.android.package-archive", ext = ["apk"], description = "Android package")
type("android.apk-set", parents = ["archive.zip", "android"], mime = "application/zip", ext = ["apkm"], description = "Set of split APKs")
type("android.axml", parents = ["android"], mime = "application/octet-stream", description = "Android binary XML")
type("android.dex", parents = ["executable", "android"], mime = "application/vnd.android.dex", ext = ["dex"], description = "Dalvik Executable")
