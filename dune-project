(lang dune 2.9)

(name yara)

(license Apache-2.0)

(use_standard_c_and_cxx_flags false)

(source
 (github elastic/ocaml-yara))

(generate_opam_files true)

(maintainers "Hezekiah Carty <hezekiah.carty@elastic.co>")

(authors "Hezekiah Carty <hezekiah.carty@elastic.co>")

(package
 (name yara)
 (synopsis "Interface to libyara")
 (depends
  (ocaml
   (>= 4.11.0))
  ctypes
  ctypes-foreign
  (base
   (and
    :with-test
    (>= v0.14)
    (< v0.15)))
  (sexplib0
   (and
    :with-test
    (>= v0.14)
    (< v0.15)))
  (ppx_expect
   (and
    :with-test
    (>= v0.14)
    (< v0.15)))
  (stdio
   (and
    :with-test
    (>= v0.14)
    (< v0.15)))))
