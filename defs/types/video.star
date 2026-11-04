"""Video and multimedia containers."""

type("video", parents = ["bytes"], abstract = True, description = "Video and multimedia containers")

type("video.avi", parents = ["video"], mime = "video/x-msvideo", ext = ["avi"], description = "AVI video")
type("video.f4v", parents = ["video"], mime = "video/mp4", ext = ["f4v"], description = "Flash MP4 video")
type("video.flv", parents = ["video"], mime = "video/x-flv", ext = ["flv"], description = "Flash video video")
type("video.m4v", parents = ["video"], mime = "video/x-m4v", ext = ["m4v"], description = "M4V video")
type("video.mkv", parents = ["video"], mime = "video/x-matroska", ext = ["mkv"], description = "Matroska video")
type("video.mov", parents = ["video"], mime = "video/quicktime", ext = ["mov"], description = "QuickTime video")
type("video.mp4", parents = ["video"], mime = "video/mp4", ext = ["mp4"], description = "MPEG-4 video")
type("video.mpeg", parents = ["video"], mime = "video/mpeg", ext = ["mpg"], description = "MPEG video")
type("video.ogv", parents = ["video"], mime = "video/ogg", ext = ["ogm", "ogv", "ogx", "opus"], description = "Ogg video video")
type("video.webm", parents = ["video"], mime = "video/webm", ext = ["webm"], description = "WebM video")
type("video.wmv", parents = ["video"], mime = "video/x-ms-wmv", ext = ["wmv"], description = "Windows Media video")
