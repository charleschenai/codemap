# COM GUID database — attribution

Source: capa (https://github.com/mandiant/capa) — Apache License 2.0
Files: `capa/features/com/classes.py` (3,682 CLSID entries),
       `capa/features/com/interfaces.py` (25,620 IID entries).

Vendored snapshot collapsed into one (guid → name) row per unique
GUID. When multiple capa names map to the same GUID, names are joined
with `|`. See `build.py` for the conversion.

License: Apache-2.0. Copyright 2024 Google LLC.
Bundled in codemap (MIT) under the Apache-2.0 license terms — see
the upstream LICENSE file at https://github.com/mandiant/capa.
