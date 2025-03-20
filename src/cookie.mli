type encrypted = Sqlite3.Data.t array
type decrypted
val decrypt : (Value.encrypted -> Value.decrypted option) -> encrypted -> decrypted option
val pp : Format.formatter -> decrypted -> unit
