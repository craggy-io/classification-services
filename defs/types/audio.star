"""Audio."""

type("audio", parents = ["bytes"], abstract = True, description = "Audio")

type("audio.aifc", parents = ["audio"], mime = "audio/x-aifc", ext = ["aifc"], description = "AIFF-C audio")
type("audio.aiff", parents = ["audio"], mime = "audio/x-aiff", ext = ["aif"], description = "AIFF audio")
type("audio.amr", parents = ["audio"], mime = "audio/amr", ext = ["amr"], description = "AMR audio")
type("audio.au", parents = ["audio"], mime = "audio/basic", ext = ["au"], description = "Sun/NeXT AU audio")
type("audio.audacity-block", parents = ["audio"], mime = "application/octet-stream", ext = ["auf"], description = "Audacity block file audio")
type("audio.flac", parents = ["audio"], mime = "audio/x-flac", ext = ["flac"], description = "FLAC audio")
type("audio.m4a", parents = ["audio"], mime = "audio/m4a", ext = ["m4a"], description = "MPEG-4 audio audio")
type("audio.midi", parents = ["audio"], mime = "audio/midi", ext = ["midi"], description = "MIDI audio")
type("audio.mp3", parents = ["audio"], mime = "audio/mpeg", ext = ["mp3"], description = "MP3 audio")
type("audio.ogg", parents = ["audio"], mime = "audio/ogg", ext = ["ogg"], description = "Ogg audio audio")
type("audio.wav", parents = ["audio"], mime = "audio/x-wav", ext = ["wav"], description = "WAVE audio")
