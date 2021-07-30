type t = {
  host_key: string ;
  subdomains: bool ;
  path: string ;
  secure: bool ;
  expires_utc: int64 ;
  name: string ;
  value: string ;
}

let decipher encrypted_data =
  let length = String.length encrypted_data in
  if
    length<3 ||
    String.get encrypted_data 0<>'v' ||
    String.get encrypted_data 1<>'1' ||
    String.get encrypted_data 2<>'0'
  then encrypted_data else begin
    let key_length = 16 in
    let key =
      let password = "peanuts" in
      let salt = "saltysalt" in
      let iterations = 1 in
      let cstruct =
        Pbkdf.pbkdf2
          ~prf:`SHA1
          ~password:(Cstruct.of_string password)
          ~salt:(Cstruct.of_string salt)
          ~count:iterations
          ~dk_len:(Int32.of_int key_length)
      in
      Mirage_crypto.Cipher_block.AES.CBC.of_secret cstruct
    in
    let iv = String.make key_length ' ' |> Cstruct.of_string in
    let encrypted_cstruct =
      String.sub encrypted_data 3 (length-3) |> Cstruct.of_string
    in
    let padded_clear_cstruct =
      Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted_cstruct
    in
    let padded_clear_data = Cstruct.to_string padded_clear_cstruct in
    let length = String.length padded_clear_data in
    if length<1 then padded_clear_data else begin
      let padding = String.get padded_clear_data (length-1) |> Char.code in
      if length<padding
      then padded_clear_data
      else String.sub padded_clear_data 0 (length-padding)
    end
  end

let of_sqlite sqlite_row =
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
  and value = match sqlite_row.(5) with
    | Sqlite3.Data.TEXT value when value<>"" -> value
    | _ ->
        match sqlite_row.(6) with
          | Sqlite3.Data.TEXT value -> value
          | Sqlite3.Data.BLOB blob -> decipher blob
          | _ -> ""
  in
  let subdomains =
    String.length host_key>0 && String.get host_key 0='.'
  in
  {
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
