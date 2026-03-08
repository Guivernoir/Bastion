# AES Core (Internal)

Implements AES-256 core primitives used by the GCM layer.

## Contents

- key schedule expansion
- block encryption transform
- key container management

## Key Handling

- Key bytes are carried in fixed-size arrays.
- Key schedule storage is zeroized during cleanup/drop paths.
- API design avoids implicit cloning of secret key state.

## Validation

- known-answer tests from AES references
- key schedule consistency checks
- avalanche and deterministic behavior sanity tests
