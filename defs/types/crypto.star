"""Keys, certificates, tokens and digests."""

type("crypto", parents = ["bytes"], abstract = True, description = "Keys, certificates, tokens and digests")

type("crypto.bitlocker-key", parents = ["crypto"], mime = "application/octet-stream", ext = ["bitlocker"], description = "BitLocker recovery key")
type("crypto.certificate", parents = ["crypto"], mime = "application/pkix-cert", ext = ["cat", "cer", "crl", "crt", "der", "p7b", "p7c", "p7m", "p7s", "rsa", "swz"], description = "Certificate or PKCS#7 container")
type("crypto.digest", parents = ["crypto", "encoding.hex"], mime = "text/plain", description = "Hexadecimal digest")
type("crypto.jwt", parents = ["crypto", "text"], mime = "application/jwt", ext = ["jwt"], description = "JSON Web Token")
type("crypto.keychain", parents = ["crypto"], mime = "application/octet-stream", ext = ["keychain"], description = "macOS keychain")
type("crypto.pem", parents = ["crypto", "text"], mime = "application/x-pem-file", ext = ["pem", "key", "crt"], description = "PEM-armoured data")
type("crypto.pgp-pubring", parents = ["crypto"], mime = "application/pgp-keys", ext = ["gpg", "pkr"], description = "PGP public keyring")
type("crypto.pgp-safe", parents = ["crypto"], mime = "application/pgp-keys", ext = ["pgd"], description = "PGP Disk / safe")
type("crypto.pgp-secring", parents = ["crypto"], mime = "application/pgp-keys", ext = ["skr"], description = "PGP secret keyring")
type("crypto.private-key", parents = ["crypto"], mime = "application/pkcs8", ext = ["key"], description = "Private key material")
type("crypto.wallet", parents = ["crypto"], mime = "application/octet-stream", ext = ["wallet"], description = "Cryptocurrency wallet")
type("crypto.x509", parents = ["crypto.certificate"], mime = "application/pkix-cert", ext = ["cer", "crt", "der", "pem"], description = "X.509 certificate (parsed)")
