release:
  cargo release

# CI tasks

check-ci:
  cargo clippy --all-targets -- -Dwarnings

format-ci:
  cargo fmt -- --check --verbose

test-ci:
  cargo tarpaulin -v --all-features --ignore-tests --out Lcov
