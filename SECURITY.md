# Security Considerations

## Intended use

This project is an educational, defensive tool for offline analysis of
authentication logs. Analyze only synthetic data or logs you are authorized
to access. Use isolated lab environments for demonstrations.

The tool does not establish whether an authentication event is malicious.
Alerts require investigation and contextual information.

## Protecting data

Logs and reports may contain usernames, IP addresses, hostnames and file paths.

- Keep real logs and generated reports outside public repositories.
- Use synthetic examples when sharing issues, screenshots or demonstrations.
- Run the CLI without administrator privileges.
- Store inputs and outputs in directories you control.
- Review reports before sharing them.

Ignore rules help prevent accidental commits but are not access controls.
They do not remove files already tracked by Git.

## Input and output boundaries

The CLI reads input bytes into memory. Very large files or dense event windows
may exhaust available resources. Apply appropriate input size limits in your
lab environment.

Only documented input formats are supported. Invalid input stops analysis.

Output files are created exclusively: existing files are not overwritten.
On POSIX systems, new reports are requested with owner-only permissions.
A failed write may leave a partial output file; inspect it before reuse.

SHA-256 identifies the analyzed input bytes. It does not establish who
created the file or whether its contents are trustworthy.

## Dependencies

The application currently has no third-party runtime dependencies.
Development tools are listed in requirements-dev.lock.

Pinned versions support reproducibility but do not guarantee security.
Review dependency updates and rerun quality checks before accepting them.

## Reporting a vulnerability

Do not include real logs, credentials or personal information in public issues.

Once this repository is hosted on GitHub, use private vulnerability reporting
if the maintainer has enabled it. Otherwise, request a private reporting
channel without publicly disclosing sensitive details.

Include the affected commit, a minimal synthetic reproduction, the expected
behavior and the observed behavior.
