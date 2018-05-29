OCAMLBUILD=ocamlbuild -use-ocamlfind

build: _build/src/main.native

test: _build/src/main.byte
	@$<

_build/src/main.native: src/main.ml
	@$(OCAMLBUILD) src/main.native

_build/src/main.byte: src/main.ml
	@$(OCAMLBUILD) src/main.byte
