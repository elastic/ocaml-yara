open Ctypes
open Foreign

type error = [ `Yara of int ]
type 'ok result = ('ok, error) Stdlib.result

let open_error = function
  | Ok _ as o -> o
  | Error (`Yara e) -> Error (`Yara e)

let pp_error fmt (`Yara e) = Format.fprintf fmt "Yara error %d" e

let error_to_msg = function
  | Ok _ as o -> o
  | Error e -> Error (`Msg (Format.asprintf "%a" pp_error e))

exception Yara_error of int

module Yr = struct
  let ok x : 'ok result = Ok x
  let error e : 'ok result = Error (`Yara e)

  let unwrap = function
    | Ok o -> o
    | Error (`Yara e) -> raise @@ Yara_error e
end

(* Try to load the yara library *)
let rec init dlls =
  match dlls with
  | [] -> None
  | filename :: tl ->
    ( try Some (Dl.dlopen ~filename ~flags:[ Dl.RTLD_NOW ]) with
    | Dl.DL_error _ -> init tl
    )
let default_from = init [ "libyara.so"; "libyara.dylib"; "yara.dll" ]

let dynamic = ref None

let init_dynamic ?lib () =
  match lib with
  | Some _ as s -> dynamic := s
  | None -> dynamic := default_from

let () = init_dynamic ()

let wrap ?release_runtime_lock ?(so = true) name t =
  let from =
    if so then
      !dynamic
    else
      None
  in
  foreign ?from ?release_runtime_lock name t

let err exn =
  view
    ~read:(fun i ->
      if i = 0 then
        ()
      else
        raise exn
    )
    ~write:(fun () -> 0)
    int

(* Setup and teardown *)
let initialize () =
  let (i, err) = Yara_c.initialize () in
  if i = 0 then
    Yr.ok ()
  else
    Yr.error (Signed.SInt.to_int err)
let initialize_exn () = Yr.unwrap @@ initialize ()

let finalize () =
  let (i, err) = Yara_c.finalize () in
  if i = 0 then
    Yr.ok ()
  else
    Yr.error (Signed.SInt.to_int err)
let finalize_exn () = Yr.unwrap @@ finalize ()

module Rule = struct
  type metadata =
    | Int of int64
    | Bool of bool
    | String of string

  type t = {
    identifier : string;
    namespace : string;
    metadata : (string * metadata) list;
  }

  let collect_metadata metas =
    let q = Queue.create () in
    let ident meta = getf meta Yara_c.Yr_meta.identifier in
    let rec loop metas =
      if not (is_null metas) then (
        let meta = !@metas in
        let flags = getf meta Yara_c.Yr_meta.flags in
        let last_in_rule = flags = Yara_c.Constants.meta_flags_last_in_rule in
        let ident = ident meta in
        match getf meta Yara_c.Yr_meta.type_ with
        | Yara_c.Meta_type.Integer ->
          let v = getf meta Yara_c.Yr_meta.integer in
          Queue.add (ident, Int v) q;
          if not last_in_rule then loop (metas +@ 1)
        | String ->
          let v = getf meta Yara_c.Yr_meta.string in
          Queue.add (ident, String v) q;
          if not last_in_rule then loop (metas +@ 1)
        | Boolean ->
          let v = getf meta Yara_c.Yr_meta.integer in
          Queue.add
            ( ident,
              Bool
                ( if v > 0L then
                  true
                else
                  false
                )
            )
            q;
          if not last_in_rule then loop (metas +@ 1)
      )
    in
    loop metas;
    List.of_seq (Queue.to_seq q)

  let from_ptr ptr =
    let rule = !@ptr in
    let ns = !@(getf rule Yara_c.Yr_rule.namespace) in
    let identifier = getf rule Yara_c.Yr_rule.identifier in
    let namespace = getf ns Yara_c.Yr_namespace.name in

    let metas = getf rule Yara_c.Yr_rule.meta in

    { identifier; namespace; metadata = collect_metadata metas }

  let get_identifier rule = rule.identifier

  let get_namespace rule = rule.namespace

  let get_metadata rule = rule.metadata
end

module Rules = struct
  type t = unit ptr
  let t : t typ = ptr void

  type message_kind =
    | Rule_matching_kind
    | Rule_not_matching_kind
    | Scan_finished_kind
    | Import_module_kind
    | Module_imported_kind

  type message =
    | Rule_matching of Rule.t
    | Rule_not_matching of Rule.t
    | Scan_finished
    | Import_module
    | Module_imported

  let message_kind_of_int = function
    | 1 -> Rule_matching_kind
    | 2 -> Rule_not_matching_kind
    | 3 -> Scan_finished_kind
    | 4 -> Import_module_kind
    | 5 -> Module_imported_kind
    | _ -> invalid_arg "unhandled yara message value"

  let int_of_message_kind = function
    | Rule_matching_kind -> 1
    | Rule_not_matching_kind -> 2
    | Scan_finished_kind -> 3
    | Import_module_kind -> 4
    | Module_imported_kind -> 5

  let message_kind =
    view ~read:message_kind_of_int ~write:int_of_message_kind int

  type callback_result =
    [ `Continue
    | `Abort
    | `Error
    ]

  let callback_of_int = function
    | 0 -> `Continue
    | 1 -> `Abort
    | 2 -> `Error
    | _ -> invalid_arg "unhandled yara callback result value"

  let int_of_callback = function
    | `Continue -> 0
    | `Abort -> 1
    | `Error -> 2

  exception Unable_to_allocate_rules

  let err_rules = err Unable_to_allocate_rules

  let destroy = wrap "yr_rules_destroy" (t @-> returning void)

  let callback_result = view ~read:callback_of_int ~write:int_of_callback int

  let callback_c =
    ptr void
    @-> message_kind
    @-> ptr void
    @-> ptr void
    @-> returning callback_result
  let callback_ptr = funptr ~runtime_lock:true callback_c

  let wrap_callback f _yara_ctx message content _user_data =
    let content =
      match message with
      | Rule_matching_kind ->
        Rule_matching (Rule.from_ptr @@ from_voidp Yara_c.Yr_rule.t content)
      | Rule_not_matching_kind ->
        Rule_not_matching (Rule.from_ptr @@ from_voidp Yara_c.Yr_rule.t content)
      | Scan_finished_kind -> Scan_finished
      | Import_module_kind -> Import_module
      | Module_imported_kind -> Module_imported
    in
    try f content with
    | _exn -> `Error

  type scan_error =
    | Insufficient_memory
    | Too_many_scan_threads
    | Scan_timeout
    | Callback_error
    | Too_many_matches

  let pp_scan_error fmt e =
    let s =
      match e with
      | Insufficient_memory -> "insufficient memory"
      | Too_many_scan_threads -> "too many scan threads"
      | Scan_timeout -> "scan timeout"
      | Callback_error -> "callback error"
      | Too_many_matches -> "too many matches"
    in
    Format.fprintf fmt "Yara compiler error (%s)" s

  type error = [ `Yara_rules of scan_error ]

  type 'ok result = ('ok, error) Stdlib.result

  let open_error (r : 'ok result) =
    match r with
    | Ok _ as o -> o
    | Error (`Yara_rules _) as e -> e

  let pp_error fmt (`Yara_rules e) =
    Format.fprintf fmt "Yara rule error %a" pp_scan_error e

  let error_to_msg = function
    | Ok _ as o -> o
    | Error e -> Error (`Msg (Format.asprintf "%a" pp_error e))

  let ok x = Ok x
  let error e = Error (`Yara_rules e)

  exception Scan_error of scan_error

  let scan_result_of_int = function
    | 0 -> ok ()
    | 1 -> error Insufficient_memory
    | 27 -> error Too_many_scan_threads
    | 26 -> error Scan_timeout
    | 28 -> error Callback_error
    | 30 -> error Too_many_matches
    | _ -> invalid_arg "unhanded yara scan result value"

  let int_of_scan_result = function
    | Ok () -> 0
    | Error (`Yara_rules Insufficient_memory) -> 1
    | Error (`Yara_rules Too_many_scan_threads) -> 27
    | Error (`Yara_rules Scan_timeout) -> 26
    | Error (`Yara_rules Callback_error) -> 28
    | Error (`Yara_rules Too_many_matches) -> 30

  let scan_result = view ~read:scan_result_of_int ~write:int_of_scan_result int

  let scan =
    wrap ~release_runtime_lock:true "yr_rules_scan_mem"
      (t
      @-> string
      @-> size_t
      @-> int
      @-> callback_ptr
      @-> ptr_opt void
      @-> int
      @-> returning scan_result
      )

  let scan ?flags ?timeout callback rules bytes =
    ignore flags;
    let timeout =
      match timeout with
      | None -> 0
      | Some t -> t
    in
    scan rules bytes
      (Unsigned.Size_t.of_int @@ String.length bytes)
      0 (wrap_callback callback) None timeout

  let scan_exn ?flags ?timeout callback rules bytes =
    let result = scan ?flags ?timeout callback rules bytes in
    match result with
    | Ok () -> ()
    | Error (`Yara_rules e) -> raise @@ Scan_error e

  let scan_names_callback ~matched ~missed message =
    let name rule = Rule.get_identifier rule in
    ( match message with
    | Rule_not_matching rule -> missed := name rule :: !missed
    | Rule_matching rule -> matched := name rule :: !matched
    | Scan_finished
    | Import_module
    | Module_imported ->
      ()
    );
    `Continue

  let scan_names ?flags ?timeout rules bytes =
    let matched = ref [] in
    let missed = ref [] in
    let result =
      scan ?flags ?timeout (scan_names_callback ~matched ~missed) rules bytes
    in
    match result with
    | Ok () -> Ok (`Matches !matched, `Misses !missed)
    | Error _ as e -> e

  let scan_names_exn ?flags ?timeout rules bytes =
    match scan_names ?flags ?timeout rules bytes with
    | Ok c -> c
    | Error (`Yara_rules e) -> raise @@ Scan_error e
end

module Compiler = struct
  type t = unit ptr
  let t : t typ = ptr void

  type error = [ `Yara_compiler of int ]

  type 'ok result = ('ok, error) Stdlib.result

  let open_error = function
    | Ok _ as o -> o
    | Error (`Yara_compiler _) as e -> e

  let pp_error fmt (`Yara_compiler i) =
    Format.fprintf fmt "Yara compiler error %d" i

  let error_to_msg = function
    | Ok _ as o -> o
    | Error e -> Error (`Msg (Format.asprintf "%a" pp_error e))

  let ok x = Ok x
  let error e = Error (`Yara_compiler e)

  exception Unable_to_allocate_compiler

  let err_compiler = err Unable_to_allocate_compiler

  let create = wrap "yr_compiler_create" (ptr t @-> returning err_compiler)
  let destroy = wrap "yr_compiler_destroy" (t @-> returning void)

  let make () =
    let compiler_p = allocate_n t ~count:1 in
    create compiler_p;
    let compiler = !@compiler_p in
    Gc.finalise destroy compiler;
    compiler

  let add_string =
    wrap "yr_compiler_add_string" (t @-> string @-> string_opt @-> returning int)
  let add_string ?namespace compiler s =
    match add_string compiler s namespace with
    | 0 -> ok ()
    | n -> error n

  let add_string_exn ?namespace compiler s =
    match add_string ?namespace compiler s with
    | Ok () -> ()
    | Error (`Yara_compiler i) ->
      invalid_arg
      @@ Printf.sprintf "Yara.Compiler.add_string_exn: %d from %s" i s

  let get_rules =
    wrap "yr_compiler_get_rules"
      (t @-> ptr Rules.t @-> returning Rules.err_rules)
  let get_rules compiler =
    let rules_p = allocate_n t ~count:1 in
    get_rules compiler rules_p;
    let rules = !@rules_p in
    Gc.finalise Rules.destroy rules;
    rules
end

let to_rules raw_rules =
  let c = Compiler.make () in
  let result =
    List.fold_left
      (fun state raw ->
        match state with
        | Ok () -> Compiler.add_string c raw
        | Error _ as e -> e
      )
      (Ok ()) raw_rules
  in
  match result with
  | Ok () -> Ok (Compiler.get_rules c)
  | Error _ as e -> e

let to_rules_exn raw_rules =
  let c = Compiler.make () in
  List.iter (fun raw -> Compiler.add_string_exn c raw) raw_rules;
  Compiler.get_rules c
