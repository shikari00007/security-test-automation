# Red-green procedure

1. Identify the vulnerable variant (revision, fixture) and the fixed variant.
2. Run the test against the vulnerable variant: it must fail for the stated reason (not an import error or missing fixture).
3. Run it against the fixed variant: it must pass.
4. Mutate once: break the fix slightly and confirm the test fails again.
5. Record both outputs (command, exit code, relevant lines) as the evidence that the test is meaningful.

CLI: `security-skills regression verify --test <file> --vulnerable <path> --fixed <path>`.

If red cannot be shown, report the test as `inconclusive` and do not present it as a guard. Never edit the application to create the red state; use a copy or fixture.
