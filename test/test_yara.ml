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

let list_to_string xs =
  List.sexp_of_t String.sexp_of_t xs
  |> Sexp.to_string_hum

let%expect_test "Can parse yara rules" =
  Yara.init_dynamic ();
  Yara.initialize_exn ();
  let rules = prepare_rule test_rule in
  match Yara.Rules.scan_names rules "Hello OCaml" with
  | Error err ->
      printf "%s" (Caml.Format.asprintf "%a" Yara.Rules.pp_error err)
  | Ok (`Matches matches, `Misses misses) ->
      printf "Matches: %s\n" (list_to_string matches);
      printf "Misses: %s\n" (list_to_string misses);
  [%expect {|
    Matches: (hello_ocam)
    Misses: () |}]
