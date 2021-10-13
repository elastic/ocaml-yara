let generate_c_stubs prefix =
  let headers = [ "#include <yara.h>" ] in
  List.iter print_endline headers;
  Cstubs.write_c ~errno:Cstubs.return_errno ~concurrency:Cstubs.unlocked
    Format.std_formatter ~prefix
    (module Yara_stubs.Definition)

let generate_ml_stubs prefix =
  Cstubs.write_ml ~errno:Cstubs.return_errno ~concurrency:Cstubs.unlocked
    Format.std_formatter ~prefix
    (module Yara_stubs.Definition)

let () =
  let generate_ml = ref false in
  let spec = [ ("-ml", Arg.Set generate_ml, "Generate OCaml") ] in
  Arg.(
    parse spec
      (fun _ -> failwith "Unexpected anonymous argument")
      "generate_yara_stubs [-ml]"
  );
  if !generate_ml then
    generate_ml_stubs "ocaml_yara_stub"
  else
    generate_c_stubs "ocaml_yara_stub"
