let () =
  let headers = [ "#include <yara/types.h>" ] in
  List.iter print_endline headers;
  Cstubs_structs.write_c Format.std_formatter (module Yara_constants.Definition)
