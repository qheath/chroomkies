type encrypted
type decrypted
val of_domain : Sqlite3.db -> string -> encrypted
val decrypt : (Cookie.encrypted -> Cookie.decrypted option) -> encrypted -> decrypted
val pp : Format.formatter -> decrypted -> unit
