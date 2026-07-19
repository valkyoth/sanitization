# CP-23 Release Preparation

CP-23 starts from the accepted CP-22 implementation state:

```text
b41c1cb8e0622eb8637261a1b62b47ba66a03183
```

The checkpoint may change only:

- workspace and internal dependency versions;
- crates.io-facing README and companion-crate documentation;
- changelog and 2.0 release notes;
- release evidence records and target-tier wording;
- package archive validation; and
- publication tooling and checkpoint state.

It must not change library source, public declarations, feature definitions,
unsafe boundaries, runtime behavior, or the CP-21 semantic API snapshots.

The CP-23 review range begins at the commit above and ends at the final CP-23
implementation or remediation commit. After acceptance, the permanent
`security/pentest/v2.0.0.md` report is committed alone and names that exact
accepted commit as `Reviewed-Commit`.
