type encrypted = string
type decrypted = string

let decrypt cookie_database_version =
  let decrypt_v10 =
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
    Mirage_crypto.AES.CBC.decrypt ~key ~iv
  in
  fun encrypted_value ->
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
        let encrypted_payload =
          String.sub encrypted_value 3 (length-3)
        in
        let padded_clear_payload =
          decrypt_v10 encrypted_payload
        in
        let length = String.length padded_clear_payload in
        if length<1 then begin
          Printf.eprintf "decrypted value is empty (padding expected)\n%!" ;
          None
        end else begin
          let padding = String.get padded_clear_payload (length-1) |> Char.code in
          let prefix_length =
            match cookie_database_version with
            | Some value when value >= 24 -> 32
            | _ -> 0
          in
          if length<padding+prefix_length then begin
            Printf.eprintf "decrypted value is too short\n%!" ;
            None
          end else Some (String.sub padded_clear_payload prefix_length (length-padding-prefix_length))
        end
      end
    end
