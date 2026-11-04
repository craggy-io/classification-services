"""Structured data and databases."""

type("data", parents = ["bytes"], abstract = True, description = "Structured data and databases")

type("data.accdb", parents = ["data"], mime = "application/msaccess", ext = ["accda", "accdb", "accde", "accdu"], description = "Microsoft Access 2007+ database")
type("data.bplist", parents = ["data.plist"], mime = "application/x-plist", ext = ["abcdp", "bplist", "ichat", "ipmeta", "mdbackup", "mdinfo", "nib", "plist", "qtz", "strings", "webbookmark", "webhistory"], description = "Binary property list")
type("data.edb", parents = ["data"], mime = "application/octet-stream", ext = ["edb"], description = "Microsoft Exchange (ESE) database")
type("data.json", parents = ["data", "text"], mime = "application/json", ext = ["json"], description = "JSON")
type("data.mdb", parents = ["data"], mime = "application/msaccess", ext = ["fdb", "mda", "mdb", "mde", "mdt", "psa"], description = "Microsoft Access (Jet) database")
type("data.outlook-dbx", parents = ["data"], mime = "application/octet-stream", ext = ["dbx"], description = "Outlook Express mailbox")
type("data.outlook-msg", parents = ["data", "document.ole2"], mime = "application/vnd.ms-outlook", ext = ["msg"], description = "Outlook message")
type("data.outlook-pst", parents = ["data"], mime = "application/octet-stream", ext = ["fdb", "ost", "pab", "pst"], description = "Outlook personal storage table")
type("data.plist", parents = ["data"], description = "Property list")
type("data.plist-xml", parents = ["data.plist", "data.xml"], mime = "application/xml", ext = ["plist"], description = "XML property list")
type("data.smile", parents = ["data"], mime = "application/x-jackson-smile", ext = ["sml"], description = "Smile (binary JSON)")
type("data.sqlite", parents = ["data"], mime = "application/vnd.sqlite3", ext = ["sqlite"], description = "SQLite 3 database")
type("data.torrent", parents = ["data"], mime = "application/x-bittorrent", ext = ["torrent"], description = "BitTorrent metainfo")
type("data.xml", parents = ["data", "text"], mime = "application/xml", ext = ["xml"], description = "XML")
