module Definition : functor (F : Ctypes.FOREIGN) -> sig
  module Constants : sig
    val meta_type_integer : int32
    val meta_type_string : int32
    val meta_type_boolean : int32
    val meta_flags_last_in_rule : int32
  end
  module Meta_type : sig
    type t =
      | Integer
      | String
      | Boolean
  end
  val meta_type : Meta_type.t Ctypes_static.typ
  module Yr_meta : sig
    type t = [ `Yara_meta ] Ctypes.structure
    val t : t Ctypes_static.typ
    val identifier : (string, t) Ctypes_static.field
    val string : (string, t) Ctypes_static.field
    val integer : (int64, t) Ctypes_static.field
    val type_ : (Meta_type.t, t) Ctypes_static.field
    val flags : (int32, t) Ctypes_static.field
  end
  module Yr_namespace : sig
    type t = [ `Yara_namespace ] Ctypes.structure
    val t : t Ctypes_static.typ
    val name : (string, t) Ctypes_static.field
    val idx : (Unsigned.uint32, t) Ctypes_static.field
  end
  module Yr_rule : sig
    type t = [ `Yara_rule ] Ctypes.structure
    val t : t Ctypes_static.typ
    val flags : (int32, t) Ctypes_static.field
    val identifier : (string, t) Ctypes_static.field
    val tags : (string, t) Ctypes_static.field
    val meta : (Yr_meta.t Ctypes_static.ptr, t) Ctypes_static.field
    val strings : (unit Ctypes_static.ptr, t) Ctypes_static.field
    val namespace : (Yr_namespace.t Ctypes_static.ptr, t) Ctypes_static.field
  end
  module Yr_rules : sig
    type t = [ `Yara_rules ] Ctypes.structure
    val t : t Ctypes_static.typ
    val rule_count : (Unsigned.uint32, t) Ctypes_static.field
    val string_count : (Unsigned.uint32, t) Ctypes_static.field
    val namespace_count : (Unsigned.uint32, t) Ctypes_static.field
    val destroy : (t Ctypes_static.ptr -> unit F.return) F.result
  end
  val initialize : (unit -> int F.return) F.result
  val finalize : (unit -> int F.return) F.result
end
