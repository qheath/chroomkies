type encrypted = Sqlite3.Data.t array
type decrypted = {
  host_key: string ;
  subdomains: bool ;
  path: string ;
  secure: bool ;
  expires_utc: int64 ;
  name: string ;
  value: string ;
}

let decrypt decrypt_value sqlite_row =
  match match sqlite_row.(5) with
    | Sqlite3.Data.TEXT value when value<>"" -> Some value
    | _ ->
        match sqlite_row.(6) with
          | Sqlite3.Data.TEXT encrypted_value
          | Sqlite3.Data.BLOB encrypted_value -> decrypt_value encrypted_value
          | _ -> None
  with
  | None ->
    Printf.eprintf "can't extract a value, skipping row\n%!" ;
    None
  | Some value ->
    let host_key = match sqlite_row.(0) with
      | Sqlite3.Data.TEXT host_key -> host_key
      | _ -> ""
    and path = match sqlite_row.(1) with
      | Sqlite3.Data.TEXT path -> path
      | _ -> ""
    and secure = sqlite_row.(2) <> Sqlite3.Data.INT 0L
    and expires_utc = match sqlite_row.(3) with
      | Sqlite3.Data.INT expires_utc when expires_utc<>0L ->
          Int64.div (Int64.sub expires_utc 11644473600000000L) 1000000L
      | _ -> 0L
    and name = match sqlite_row.(4) with
      | Sqlite3.Data.TEXT name -> name
      | _ -> ""
    in
    let subdomains =
      String.length host_key>0 && String.get host_key 0='.'
    in
    Some {
      host_key ;
      subdomains ;
      path ;
      secure ;
      expires_utc ;
      name ;
      value ;
    }

let pp fmt decrypted_cookie =
  let string_of_bool b = if b then "TRUE" else "FALSE" in
  let {
    host_key ;
    subdomains ;
    path ;
    secure ;
    expires_utc ;
    name ;
    value ;
  } = decrypted_cookie in
  Format.fprintf fmt "%s\t%s\t%s\t%s\t%Ld\t%s\t%s\n"
    host_key (string_of_bool subdomains) path (string_of_bool secure)
    expires_utc name value
