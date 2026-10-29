# Helpers shared by install-plugin.sh and uninstall-plugin.sh: where libfprint looks for TOD
# drivers, and quoting for the commands printed for a root shell.
#
# Sourced, never executed. The caller sets `caller_dir` to the directory it was invoked from, before
# changing its own working directory: a relative CV3_TOD_DIR is resolved against that directory, not
# against the repository.

# The one file this project installs.
tod_plugin_name=libfprint-2-tod-1-cv3.so

# Where libfprint's TOD loader looks. pkg-config knows the path as `tod_driversdir`; older
# pkg-config files do not define it, so fall back to libdir/libfprint-2/tod-1, which is where the
# library has always put them.
tod_default_dir() {
    _tod_dir=$(pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null || true)
    if [ -z "$_tod_dir" ]; then
        _tod_libdir=$(pkg-config --variable=libdir libfprint-2-tod-1 2>/dev/null || true)
        if [ -z "$_tod_libdir" ]; then
            echo "error: pkg-config cannot find libfprint-2-tod-1; install libfprint-2-tod-dev" >&2
            return 1
        fi
        _tod_dir=$_tod_libdir/libfprint-2/tod-1
    fi
    printf '%s\n' "$_tod_dir"
}

# The directory to install into or remove from, absolute.
tod_dir() {
    _tod_dir=${CV3_TOD_DIR:-$(tod_default_dir)}
    case $_tod_dir in
    /*) ;;
    *) _tod_dir=$caller_dir/$_tod_dir ;;
    esac
    printf '%s\n' "$_tod_dir"
}

# Prints an argument shell-quoted, for a command the reader pastes into a root shell.
quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}
