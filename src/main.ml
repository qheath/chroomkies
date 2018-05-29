(* https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/ *)

let now = Unix.time () |> int_of_float |> string_of_int
let hostname = Unix.gethostname ()
let cwd = Sys.getcwd ()

let chromium_cookies_db_file =
  Printf.sprintf "%s/.config/chromium/Default/Cookies" (Sys.getenv "HOME")

let copy_cookies_db_file =
  Filename.temp_file now hostname

let copy in_file out_file =
  let ic = open_in_bin in_file
  and oc = open_out_bin out_file in
  let buf_len = 128 in
  let buf = Bytes.create buf_len in
  let rec aux () =
    let len = input ic buf 0 buf_len in
    if len>0 then begin
      output oc buf 0 len ;
      aux ()
    end else begin
      close_in ic ;
      close_out oc
    end
  in
  aux () ;
  Printf.eprintf "%S written\n%!" out_file

let () =
  copy chromium_cookies_db_file copy_cookies_db_file

let step_by_step cb seed statement =
  let rec aux accum =
    match Sqlite3.step statement with
      | Sqlite3.Rc.ROW ->
          let row = Sqlite3.row_data statement in
          let accum = cb accum row in
          aux accum
      | Sqlite3.Rc.DONE -> accum
      | _ ->
          Printf.eprintf "something went wrongly\n%!" ;
          accum
  in
  aux seed

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
      Nocrypto.Cipher_block.AES.CBC.of_secret cstruct
    in
    let iv = String.make key_length ' ' |> Cstruct.of_string in
    let encrypted_cstruct =
      String.sub encrypted_data 3 (length-3) |> Cstruct.of_string
    in
    let padded_clear_cstruct =
      Nocrypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted_cstruct
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
    (*
  let aux derived_key =
    let decipher = () in
    let decoded = () in
    let final = () in
    let padding = () in
    decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(false);
    encryptedData = encryptedData.slice(3);
    decoded = decipher.update(encryptedData);
    final = decipher.final();
    final.copy(decoded, decoded.length - 1);
    padding = decoded[decoded.length - 1];
    if (padding) {
    decoded = decoded.slice(0, decoded.length - padding);
    }
    decoded = decoded.toString('utf8');
    return decoded;
  in
  crypto.pbkdf2 chromePassword salt iterations key_length "sha1" aux
     *)

let x =
  let db = Sqlite3.db_open ~mode:`READONLY copy_cookies_db_file in
  let statement =
    Sqlite3.prepare db
      (Printf.sprintf
         "SELECT host_key,path,secure,expires_utc,name,value,encrypted_value FROM cookies WHERE host_key like '%s'"
         "%.youtube.com")
  in
  let _ = Sqlite3.reset statement in
  let handle accum row =
    let host_key = match row.(0) with
      | Sqlite3.Data.TEXT host_key -> host_key
      | _ -> ""
    in
    let subdomains =
      if String.length host_key>0 && String.get host_key 0='.'
      then "TRUE"
      else "FALSE"
    in
    let path = match row.(1) with
      | Sqlite3.Data.TEXT path -> path
      | _ -> ""
    in
    let secure = match row.(2) with
      | Sqlite3.Data.INT 0L -> "FALSE"
      | _ -> "TRUE"
    in
    let expires_utc = match row.(3) with
      | Sqlite3.Data.INT expires_utc when expires_utc<>0L ->
          Int64.div (Int64.sub expires_utc 11644473600000000L) 1000000L
      | _ -> 0L
    in
    let name = match row.(4) with
      | Sqlite3.Data.TEXT name -> name
      | _ -> ""
    in
    let value = match row.(5) with
      | Sqlite3.Data.TEXT value when value<>"" -> value
      | _ ->
          match row.(6) with
            | Sqlite3.Data.TEXT value -> value
            | Sqlite3.Data.BLOB blob -> decipher blob
            | _ -> ""
    in
    let row = host_key,subdomains,path,secure,expires_utc,name,value in
    row::accum
  in
  let print_row (host_key,subdomains,path,secure,expires_utc,name,value) =
    Printf.eprintf "%s\t%s\t%s\t%s\t%Ld\t%s\t%s\n%!"
      host_key subdomains path secure expires_utc name value
  in
  let rows =
    step_by_step handle [] statement
  in
  let () = List.iter print_row rows in
  let _ =
    Sqlite3.finalize statement
  in

  while (not (Sqlite3.db_close db)) do
    Printf.eprintf "database busy, trying to close again in 1 second\n%!" ;
    Unix.sleep 1
  done
