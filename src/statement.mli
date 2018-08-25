type t
val of_domain : Sqlite3.db -> string -> t
val pp : Format.formatter -> t -> unit
