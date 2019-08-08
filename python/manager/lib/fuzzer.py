import shlex

from lib import errors


def _create_state_file(state):
    # TODO: possibly obsolete
    tmpdir = os.path.join(self.outdir, 'tmp')
    os.makedirs(tmpdir, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=tmpdir, delete=False) as f:
        f.write(contents.encode('utf-8'))
        return f.name


def bat_escape(args):
    """Quote a set of arguments for a windows command line.

    Double-quote each argument, and backslash-escape any backslashes before
    double quotes and the double quotes themselves. Finally, put a ^ before
    each shell metacharacter so it will survive cmd.exe. Based on the algorithm in
    https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
    """
    escaped_args = []
    for arg in args:
        escaped_parts = ['"']
        num_backslashes = 0
        for c in arg:
            if c == '\\':
                num_backslashes += 1
            elif c == '"':
                escaped_parts.append('\\'*(2*num_backslashes+1) + c)
                num_backslashes = 0
            else:
                escaped_parts.append('\\'*num_backslashes + c)
                num_backslashes = 0
        escaped_parts.append('\\'*(2*num_backslashes) + '"')
        escaped_args.append(''.join(escaped_parts))
    final_cmdline = ' '.join(escaped_args)

    # That is what we want to be passed to CreateProcess; however, cmd is going
    # to mangle it first so we must escape all chars it considers special.
    metachars = ['(', ')', '%', '!', '^', '"', '<', '>', '&', '|']
    for char in metachars:
        final_cmdline = final_cmdline.replace(char, '^'+char)
    return '%1 {}'.format(final_cmdline)


def sh_escape(args):
    escaped_args = [shlex.quote(arg) for arg in args]
    # The >&2 redirects stdout to stderr, which will make it show up in the
    # BOINC UI
    return '$1 >&2 {}'.format(' '.join(escaped_args))


def format_cmdline(
        driver, instrumentation, mutator, iterations, shell_format,
        driver_options=None, instrumentation_options=None,
        mutator_options=None, instrumentation_state=None, mutator_state=None):
    # BOINC takes care of renaming the seed file for us
    args = [driver, instrumentation, mutator, '-sf', 'seed', '-n', str(iterations)]
    if instrumentation_options:
        args.extend(["-i", instrumentation_options])
    if mutator_options:
        args.extend(["-m", mutator_options])
    if driver_options:
        args.extend(["-d", driver_options])
    # TODO - we can't create files client-side so we have to have a way to
    # bundle these
    # if instrumentation_state:
    #     filename = self.create_state_file(instrumentation_state)
    #     args.extend(["-isf", filename])
    # if mutator_state):
    #     filename = self.create_state_file(mutator_state)
    #     args.extend(["-msf", filename])

    # In order to make this command line work on the target platform, it needs
    # to be escaped. The shell_format value comes from a config option
    # platform_opts_shell_format, however it could also be a column of the
    # target, or we could just choose a format based on the target's platform.
    # When we are working on automated target adding, we should revisit this to
    # see what works best.
    if shell_format == 'sh':
        return sh_escape(args)
    elif shell_format == 'bat':
        return bat_escape(args)
    else:
        if shell_format:
            raise errors.InputError('Unknown shell_format "{}"'.format(shell_format))
        else:
            raise errors.InputError(
                'This target has no shell_format configured. Set the '
                'platform_opts_shell_format config option.')
