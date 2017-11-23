open Printf

type filename = string
type bits = Bits32 | Bits64
type mode = Headless | Graphical

type t = {
  exec : filename;
  bits : bits;
  mode : mode;
}

type script_type = [ `Idc | `Python ]

(* Ensure the directory separator is universal *)
let feature_rex = Str.regexp @@ Filename.concat ".*" "ida\\(l\\|q\\)\\(64\\)?$"

let rec input_ignore_all ic =
  try
    input_char ic |> ignore;
    input_ignore_all ic
  with
    | _ -> ()

let create ~path =
  if Sys.file_exists path && Str.string_match feature_rex path 0 then
    Some {
      exec = path;
      bits = if try Str.matched_group 2 path = "64" with _ -> false then Bits64 else Bits32;
      mode = if Str.matched_group 1 path = "l" then Headless else Graphical;
    }
  else
    None

let database_extension ~t = if t.bits = Bits32 then ".idb" else ".i64"

let run ?(script_type = `Idc) ?(remove_database = false) ~t ~script target =
  let script_file =
    Filename.temp_file "ida_" ("_scr" ^ if script_type = `Idc then ".idc" else ".py")
  in
  let ret =
    begin try
      (* Write script to temporary file *)
      let oc = open_out script_file in
      output_string oc script;
      flush oc;
      close_out_noerr oc;

      (* Enable headless mode for TVision library *)
      if t.mode = Headless then Unix.putenv "TVHEADLESS" "1";

      (* Execute IDA to run the given script *)
      let ic = Unix.open_process_in (sprintf "%s -A -S%s %s" t.exec script_file target) in
      input_ignore_all ic;

      Unix.close_process_in ic = Unix.WEXITED 0
    with
      | _ -> false
    end
  in
  Sys.remove script_file;
  if remove_database then Sys.remove @@ target ^ database_extension ~t;
  ret
