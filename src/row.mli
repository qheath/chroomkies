type t
val of_sqlite : Sqlite3.Data.t array -> t
val pp : Format.formatter -> t -> unit
