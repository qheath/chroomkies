type t = {
  host_key: string ;
  subdomains: bool ;
  path: string ;
  secure: bool ;
  expires_utc: int64 ;
  name: string ;
  value: string ;
}

let decipher encrypted_value =
  let length = String.length encrypted_value in
  if
    length<3 ||
    String.get encrypted_value 0<>'v'
  then begin
    Printf.eprintf "encrypted value format unknown\n%!" ;
    None
  end else begin
    let version = String.sub encrypted_value 1 2 in
    if version <> "10" then begin
      Printf.eprintf "encrypted value format version %S unsupported\n%!"
        version ;
      None
    end else begin
      let key_length = 16 in
      let key =
        let password = "peanuts" in
        let salt = "saltysalt" in
        let iterations = 1 in
        let secret =
          Pbkdf.pbkdf2
            ~prf:`SHA1
            ~password:password
            ~salt:salt
            ~count:iterations
            ~dk_len:(Int32.of_int key_length)
        in
        Mirage_crypto.AES.CBC.of_secret secret
      in
      let iv = String.make key_length ' ' in
      let encrypted_payload =
        String.sub encrypted_value 3 (length-3)
      in
      let padded_clear_payload =
        Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted_payload
      in
      let length = String.length padded_clear_payload in
      let value =
        if length<1 then padded_clear_payload else begin
          let padding = String.get padded_clear_payload (length-1) |> Char.code in
          if length<padding
          then padded_clear_payload
          else String.sub padded_clear_payload 0 (length-padding)
        end
      in
      Some value
    end
  end

let of_sqlite sqlite_row =
  match match sqlite_row.(5) with
    | Sqlite3.Data.TEXT value when value<>"" -> Some value
    | _ ->
        match sqlite_row.(6) with
          | Sqlite3.Data.TEXT encrypted_value
          | Sqlite3.Data.BLOB encrypted_value -> decipher encrypted_value
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

let pp fmt row =
  let string_of_bool b = if b then "TRUE" else "FALSE" in
  let {
    host_key ;
    subdomains ;
    path ;
    secure ;
    expires_utc ;
    name ;
    value ;
  } = row in
  Format.fprintf fmt "%s\t%s\t%s\t%s\t%Ld\t%s\t%s\n"
    host_key (string_of_bool subdomains) path (string_of_bool secure)
    expires_utc name value
