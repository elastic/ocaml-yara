open Base
open Stdio

let test_rule =
  {|rule hello_ocaml {
  meta:
    category = "test"
    version = 1
    test_bool = false

  strings:
    $ocaml = "OCaml"

  condition:
    $ocaml
}|}

let prepare_rule rule =
  let compiler = Yara.Compiler.make () in
  Yara.Compiler.add_string_exn compiler rule;
  Yara.Compiler.get_rules compiler

let list_to_string xs = List.sexp_of_t String.sexp_of_t xs |> Sexp.to_string_hum

let%expect_test "Can scan for rule names" =
  Yara.init_dynamic ();
  Yara.initialize_exn ();
  let rules = prepare_rule test_rule in
  match Yara.Rules.scan_names rules "Hello OCaml" with
  | Error err -> printf "%s" (Caml.Format.asprintf "%a" Yara.Rules.pp_error err)
  | Ok (`Matches matches, `Misses misses) ->
    printf "Matches: %s\n" (list_to_string matches);
    printf "Misses: %s\n" (list_to_string misses);
    [%expect {|
    Matches: (hello_ocaml)
    Misses: () |}]

let scan_matching_rules_callback matched message =
  ( match message with
  | Yara.Rules.Rule_not_matching _ -> ()
  | Rule_matching rule -> matched := rule :: !matched
  | Scan_finished
  | Import_module
  | Module_imported ->
    ()
  );
  `Continue

let scan_matching_rules rules input =
  let matched = ref [] in
  let result =
    Yara.Rules.scan (scan_matching_rules_callback matched) rules input
  in
  match result with
  | Ok () -> Ok !matched
  | Error _ as e -> e

let sexp_of_rule t =
  let sexp_of_metadata (kind : Yara.Rule.metadata) =
    match kind with
    | Yara.Rule.Int i -> [%sexp_of: int64] i
    | Bool b -> [%sexp_of: bool] b
    | String s -> [%sexp_of: string] s
  in
  let identifier = Yara.Rule.get_identifier t in
  let namespace = Yara.Rule.get_namespace t in
  let metas = Yara.Rule.get_metadata t in
  [%sexp_of: string * string * (string * metadata) list]
    (identifier, namespace, metas)

let%expect_test "Can parse yara rules with metadata" =
  Yara.init_dynamic ();
  Yara.initialize_exn ();
  let rules = prepare_rule test_rule in
  match scan_matching_rules rules "Hello OCaml" with
  | Error err -> printf "%s" (Caml.Format.asprintf "%a" Yara.Rules.pp_error err)
  | Ok rules ->
    print_s (sexp_of_list sexp_of_rule rules);
    [%expect
      {| ((hello_ocaml default ((category test) (version 1) (test_bool false)))) |}]
