# Security Policy

## Reporting

If you believe you have found a security issue in `continue-profiling-agent`, please do not open a public issue with full exploit details.

Report the issue privately to the maintainers through the security contact channel used by your distribution of this repository. Include:

- affected version or commit
- environment and kernel version
- impact summary
- reproduction steps or proof of concept

## Scope

Security reports are especially useful for:

- privilege boundary issues
- unsafe handling of profile input data
- BPF loader or verifier bypass assumptions
- filesystem or temporary-directory vulnerabilities
- crashes or memory corruption reachable from normal CLI use

## Supported Versions

Security fixes are provided for versions maintained in this repository unless
maintainers state otherwise.
