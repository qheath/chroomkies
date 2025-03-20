type encrypted = Sqlite3.stmt
type decrypted = Cookie.decrypted list

let of_domain db domain =
  Sqlite3.prepare db
    (Printf.sprintf
       "SELECT host_key,path,is_secure,expires_utc,name,value,encrypted_value FROM cookies WHERE host_key like '%s'"
       domain)

let fold f items =
  let rec aux accum =
    match Sqlite3.step items with
      | Sqlite3.Rc.ROW ->
          let item = Sqlite3.row_data items in
          aux @@ f item accum
      | Sqlite3.Rc.DONE -> accum
      | _ ->
        Printf.eprintf "something went wrongly\n%!" ;
        accum
  in
  fun seed ->
    let _ = Sqlite3.reset items in
    let accum = aux seed in
    let _ = Sqlite3.finalize items in
    accum

let decrypt decrypt_cookie encrypted_cookiejar =
  let f encrypted_cookie reversed_decrypted_cookiejar =
    match decrypt_cookie encrypted_cookie with
    | None -> reversed_decrypted_cookiejar
    | Some decrypted_cookie -> decrypted_cookie :: reversed_decrypted_cookiejar
  in
  List.rev @@ fold f encrypted_cookiejar []

let pp fmt decrypted_cookiejar =
  List.iter (Cookie.pp fmt) decrypted_cookiejar
