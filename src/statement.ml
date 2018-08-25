type t = Sqlite3.stmt

let of_domain db domain =
  Sqlite3.prepare db
    (Printf.sprintf
       "SELECT host_key,path,is_secure,expires_utc,name,value,encrypted_value FROM cookies WHERE host_key like '%s'"
       domain)

let iter cb statement =
  let rec aux () =
    match Sqlite3.step statement with
      | Sqlite3.Rc.ROW ->
          let row = Sqlite3.row_data statement in
          cb row ;
          aux ()
      | Sqlite3.Rc.DONE -> ()
      | _ -> Printf.eprintf "something went wrongly\n%!"
  in
  aux ()

let pp_row fmt row =
  Row.pp fmt @@ Row.of_sqlite row

let pp fmt statement =
  let _ = Sqlite3.reset statement in
  iter (pp_row fmt) statement ;
  let _ = Sqlite3.finalize statement in
  ()
