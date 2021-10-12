module Definition (T : Cstubs.Types.TYPE) = struct
  open T

  let meta_type_integer = constant "META_TYPE_INTEGER" int32_t
  let meta_type_string = constant "META_TYPE_STRING" int32_t
  let meta_type_boolean = constant "META_TYPE_BOOLEAN" int32_t
end
