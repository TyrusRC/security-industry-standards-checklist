# Contributing

Thanks for helping. Please open an issue first for large changes.

## Rules for test cases

1. Write from the standard's own text. Do not copy long passages and do not write from memory.
2. One test per verifiable control. If two sources describe the same control, add both IDs to `refs` of one test. If another test already covers it, add its ID to `see`.
3. Follow `guide/schema.md`. Every test lists the source files you read in `sources_read`.
4. Use `guide/style-guide-ste100.md`: short sentences, imperative steps, approved words.
5. Pick the severity from `guide/severity-rubric.md`.
6. Reference only IDs that exist in `catalog/`. Add a catalog entry from the official source if one is missing.
7. Put commands and payload hints in `example`. Keep them at assessment level.

## Check your change

```
python3 tools/validate.py data
python3 tools/ste_lint.py data
python3 tools/check_mappings.py
```

Then regenerate the outputs:

```
python3 tools/build.py
python3 tools/export_site.py
```

## Add a new source

1. Add the source text under `sources/<name>/` (not committed) and record its version and URL.
2. Add or extend a catalog file in `catalog/`.
3. Add the key to `tools/validate.py` and `tools/export_site.py`.
4. Write the tests and run the checks above.

## Licensing

By contributing you agree that code is licensed under Apache-2.0 and checklist content under CC BY-SA 4.0. Do not add text from sources whose licence does not allow it. Requirement numbers and short titles are acceptable for copyrighted standards.
