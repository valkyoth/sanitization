#!/usr/bin/env sh
set -eu

toolchain="$(
    sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml | sed -n '1p'
)"

if [ -z "$toolchain" ]; then
    echo "ci rust: rust-toolchain.toml is missing a channel" >&2
    exit 1
fi

add_cargo_path() {
    if [ -n "${GITHUB_PATH:-}" ]; then
        printf '%s\n' "$HOME/.cargo/bin" >> "$GITHUB_PATH"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

add_ci_cargo_wrapper() {
    if [ -z "${GITHUB_PATH:-}" ]; then
        return
    fi

    wrapper_dir="${RUNNER_TEMP:-/tmp}/sanitization-rust-bin"
    mkdir -p "$wrapper_dir"
    {
        printf '%s\n' '#!/usr/bin/env sh'
        printf '%s\n' 'case "${1:-}" in'
        printf '%s\n' '    +*)'
        printf '%s\n' '        toolchain="${1#+}"'
        printf '%s\n' '        shift'
        printf '%s\n' '        exec rustup run "$toolchain" cargo "$@"'
        printf '%s\n' '        ;;'
        printf '%s\n' 'esac'
        printf 'exec rustup run %s cargo "$@"\n' "$toolchain"
    } > "$wrapper_dir/cargo"
    chmod +x "$wrapper_dir/cargo"

    printf '%s\n' "$wrapper_dir" >> "$GITHUB_PATH"
    export PATH="$wrapper_dir:$PATH"
}

install_rustup() {
    rustup_init_version='1.29.3'

    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*)
            echo "ci rust: rustup/cargo is broken on Windows; use the runner Rust install" >&2
            exit 1
            ;;
        Linux)
            case "$(uname -m)" in
                x86_64 | amd64)
                    rustup_target='x86_64-unknown-linux-gnu'
                    rustup_sha256='b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55'
                    ;;
                aarch64 | arm64)
                    rustup_target='aarch64-unknown-linux-gnu'
                    rustup_sha256='9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282'
                    ;;
                *)
                    echo "ci rust: unsupported Linux architecture: $(uname -m)" >&2
                    exit 1
                    ;;
            esac
            ;;
        Darwin)
            case "$(uname -m)" in
                x86_64 | amd64)
                    rustup_target='x86_64-apple-darwin'
                    rustup_sha256='bc107f1fb0228de7fa32413c89c1b305cea9cd256e94b01150cd054128145429'
                    ;;
                aarch64 | arm64)
                    rustup_target='aarch64-apple-darwin'
                    rustup_sha256='63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f'
                    ;;
                *)
                    echo "ci rust: unsupported macOS architecture: $(uname -m)" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "ci rust: unsupported installer platform: $(uname -s)" >&2
            exit 1
            ;;
    esac

    install_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sanitization-rustup.XXXXXX")"
    installer="$install_dir/rustup-init"
    installer_url="https://static.rust-lang.org/rustup/archive/$rustup_init_version/$rustup_target/rustup-init"

    echo "ci rust: installing pinned rustup $rustup_init_version for $rustup_target"
    curl --proto '=https' --tlsv1.2 -fsSL --output "$installer" "$installer_url"

    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  %s\n' "$rustup_sha256" "$installer" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha256="$(shasum -a 256 "$installer" | awk '{print $1}')"
        if [ "$actual_sha256" != "$rustup_sha256" ]; then
            echo "ci rust: rustup-init SHA-256 mismatch" >&2
            rm -rf "$install_dir"
            exit 1
        fi
    else
        echo "ci rust: no SHA-256 verifier is available" >&2
        rm -rf "$install_dir"
        exit 1
    fi

    chmod 755 "$installer"
    if "$installer" -y --profile minimal --default-toolchain none; then
        rm -rf "$install_dir"
    else
        status=$?
        rm -rf "$install_dir"
        return "$status"
    fi
    add_cargo_path
}

add_cargo_path

if ! command -v rustup >/dev/null 2>&1; then
    install_rustup
fi

if ! cargo --version >/dev/null 2>&1; then
    echo "ci rust: cargo proxy is not usable before toolchain setup; reinstalling rustup"
    install_rustup
fi

rustup set profile minimal
rustup toolchain install "$toolchain" --component clippy --component rustfmt
rustup default "$toolchain"
add_ci_cargo_wrapper

if ! cargo --version >/dev/null 2>&1; then
    echo "ci rust: cargo proxy is still not usable after toolchain setup" >&2
    exit 1
fi

rustup show
cargo --version
rustc --version
