(lang dune 2.9)

(name yara)

(license Apache-2.0)

(source (github elastic/ocaml-yara))

(generate_opam_files true)

(maintainers "Hezekiah Carty <hezekiah.carty@elastic.co>")
(authors "Hezekiah Carty <hezekiah.carty@elastic.co>")

(package
  (name yara)
  (synopsis "Interface to libyara")
  (depends
    (ocaml (>= 4.07.0))
    ctypes
    ctypes-foreign))
