(* https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/ *)

let now = Unix.time () |> int_of_float |> string_of_int
let hostname = Unix.gethostname ()

let make_copy in_file =
  let out_file = Filename.temp_file now hostname in
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
  Printf.eprintf "Using temp file %S...\n%!" out_file ;
  out_file

let main pattern cookiejar output =
  let fmt,close =
    if output="-" then
      Format.std_formatter,(fun () -> ())
    else
      let oc = open_out output in
      Format.formatter_of_out_channel oc,(fun () -> close_out oc)
  in
  Printf.eprintf "Getting the cookies for the domain pattern %S:\n%!" pattern ;
  let db = cookiejar |> make_copy |> Sqlite3.db_open ~mode:`READONLY in
  Format.fprintf fmt "# HTTP Cookie File\n%a%!"
    Statement.pp (Statement.of_domain db pattern) ;
  close () ;
  while (not (Sqlite3.db_close db)) do
    Printf.eprintf "database busy, trying to close again in 1 second\n%!" ;
    Unix.sleep 1
  done

let () =
  let pattern =
    let doc = "pattern to match" in
    Cmdliner.Arg.(value & opt string "%.youtube.com" & info ["p";"pattern"] ~docv:"domain_pattern" ~doc)
  and cookiejar =
    let doc = "cookies database" in
    let default =
      Printf.sprintf "%s/.config/chromium/Default/Cookies" (Sys.getenv "HOME")
    in
    Cmdliner.Arg.(value & opt file default & info ["c";"cookiejar"] ~docv:"cookiejar_path" ~doc)
  and output =
    let doc = "output file" in
    Cmdliner.Arg.(value & pos 0 string "-" & info [] ~docv:"output_path" ~doc)
  in
  let term = Cmdliner.Term.(const main $ pattern $ cookiejar $ output) in
  Cmdliner.Term.(exit @@ eval (term,(info "chroomkies")))
