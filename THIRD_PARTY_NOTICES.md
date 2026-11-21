# Third-Party Notices

This file records the provenance and license of third-party material bundled with LocalGuard.

## Bundled Semgrep rules (`localguard/rules/security-extended.json`)

The rules in `security-extended.json` are derived from the **VulnShop** benchmark rules published by
`laugiov/code-safety`, licensed under the **MIT License**:

> MIT License
>
> Copyright (c) 2025 Taint Analysis Masterclass Contributors
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

**Modification notice:** rule identifiers were prefixed with `lg.ext.` to avoid
collisions with LocalGuard's built-in rules. Rule logic is otherwise unchanged.

Source: https://github.com/laugiov/code-safety (path: `analysis/semgrep/rules/`)

## Rules intentionally NOT bundled

Rules from the official `semgrep/semgrep-rules` repository were evaluated during
development but **removed** from the distributed rule pack because the Semgrep
Rules License v1.0 restricts use to internal business purposes and prohibits
redistribution. They are not part of this distribution.
