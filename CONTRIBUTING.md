# Contributing

Thanks for taking the time to contribute to NetGuard.

## Development workflow

1. Create a feature branch from `main`.
2. Keep changes focused and easy to review.
3. Build and test locally before opening a PR.
4. Update documentation when behavior or usage changes.

## Local validation

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
./build/tests/netguard_tests
```

## Coding expectations

- Prefer clear naming over clever abstractions.
- Keep threading and concurrency behavior safe and explicit.
- Maintain compatibility with the project’s C++20 standard.
- Prefer small, testable changes.

## Pull requests

Open a PR with:

- a concise summary of the change
- affected components
- validation commands and results
- any follow-up work or known limitations
