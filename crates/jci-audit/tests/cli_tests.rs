//! CLI snapshot tests (trycmd). Snapshots live in `tests/cmd/*.trycmd`.
//! Regenerate after intentional CLI changes with `TRYCMD=overwrite cargo test`.

#[test]
fn cli_tests() {
    trycmd::TestCases::new().case("tests/cmd/*.trycmd");
}
