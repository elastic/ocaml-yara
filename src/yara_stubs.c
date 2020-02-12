/* The "usual" OCaml includes */
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/misc.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>
#include <caml/custom.h>

#include <yara.h>

#define Yr_rule_val(val) ((YR_RULE *) Nativeint_val(val))

value ml_yr_rule_get_identifier(value rule) {
    CAMLparam1(rule);

    CAMLreturn(caml_copy_string(Yr_rule_val(rule)->identifier));
}

value ml_yr_rule_get_namespace(value rule) {
    CAMLparam1(rule);

    CAMLreturn(caml_copy_string(Yr_rule_val(rule)->ns->name));
}
