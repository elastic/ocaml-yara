open Base
open Stdio

let rule1 =
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

let rule2 =
  {|rule second_rule {

  strings:
    $ocaml = "Hello"

  condition:
    $ocaml
}|}

let prepare_rule ?namespace rules =
  let compiler = Yara.Compiler.make () in
  List.iter rules ~f:(fun rule ->
      Yara.Compiler.add_string_exn ?namespace compiler rule
  );
  Yara.Compiler.get_rules compiler

let list_to_string xs = List.sexp_of_t String.sexp_of_t xs |> Sexp.to_string_hum

let%expect_test "Can scan for rule names" =
  Yara.init_dynamic ();
  Yara.initialize_exn ();
  let rules = prepare_rule [ rule1; rule2 ] in
  match Yara.Rules.scan_names rules "Hello OCaml" with
  | Error err -> printf "%s" (Caml.Format.asprintf "%a" Yara.Rules.pp_error err)
  | Ok (`Matches matches, `Misses misses) ->
    printf "Matches: %s\n" (list_to_string matches);
    printf "Misses: %s\n" (list_to_string misses);
    [%expect {|
    Matches: (second_rule hello_ocaml)
    Misses: () |}]

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
  let rules = prepare_rule ~namespace:"MyNamespace" [ rule1; rule2 ] in
  match Yara.Rules.scan_rules rules "Hello OCaml" with
  | Error err -> printf "%s" (Caml.Format.asprintf "%a" Yara.Rules.pp_error err)
  | Ok (`Matches rules, `Misses misses) ->
    print_endline "Matches: ";
    print_s (sexp_of_list sexp_of_rule rules);
    print_endline "Misses: ";
    print_s (sexp_of_list sexp_of_rule misses);
    [%expect
      {|
        Matches:
        ((second_rule MyNamespace ())
         (hello_ocaml MyNamespace ((category test) (version 1) (test_bool false))))
        Misses:
        () |}]
