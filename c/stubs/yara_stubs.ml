module Definition (F : Cstubs.FOREIGN) = struct
  module Constants = Yara_constants.Definition (Yara_generated_constants)

  module Ctypes = struct
    include Ctypes

    let ( @-> ) = F.( @-> )

    let returning = F.returning
    let foreign = F.foreign
  end

  open Ctypes

  module Meta_type = struct
    type t =
      | Integer
      | String
      | Boolean
      | Unknown of int32

    let of_int32 t =
      if t = Constants.meta_type_boolean then
        Boolean
      else if t = Constants.meta_type_integer then
        Integer
      else if t = Constants.meta_type_string then
        String
      else
        Unknown t

    let to_int32 = function
      | Integer -> Constants.meta_type_integer
      | Boolean -> Constants.meta_type_boolean
      | String -> Constants.meta_type_string
      | Unknown t -> t
  end

  let meta_type =
    view ~read:Meta_type.of_int32 ~write:Meta_type.to_int32 int32_t

  module Yr_meta = struct
    type t = [ `Yara_meta ] Ctypes.structure

    let t : t typ = structure "YR_META"

    let identifier = field t "identifier" string
    let string = field t "string" string

    let integer = field t "integer" int64_t
    let type_ = field t "type" meta_type
    let flags = field t "flags" int32_t
    (* let () = seal t *)
  end

  module Yr_namespace = struct
    type t = [ `Yara_namespace ] Ctypes.structure
    let t : t typ = structure "YR_NAMESPACE"

    let name = field t "name" string
    let idx = field t "idx" uint32_t

    let () = seal t
  end

  module Yr_rule = struct
    type t = [ `Yara_rule ] Ctypes.structure
    let t : t typ = structure "YR_RULE"
    let flags = field t "flags" int32_t

    let identifier = field t "identifier" string
    let tags = field t "tags" string
    let meta = field t "metas" (ptr void)
    let strings = field t "strings" (ptr void)
    let namespace = field t "ns" (ptr Yr_namespace.t)

    let () = seal t
  end

  module Yr_rules = struct
    type t = [ `Yara_rules ] Ctypes.structure
    let t : t typ = structure "YR_RULES"

    let rule_count = field t "num_rules" uint32_t
    let string_count = field t "num_strings" uint32_t
    let namespace_count = field t "num_namespaces" uint32_t

    (* let () = seal t *)

    let destroy = foreign "yr_rules_destroy" (ptr t @-> returning void)
  end

  let initialize = foreign "yr_initialize" (void @-> returning int)

  let finalize = foreign "yr_finalize" (void @-> returning int)
end
