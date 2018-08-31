def _create_state_file(state):
    # TODO: possibly obsolete
    tmpdir = os.path.join(self.outdir, 'tmp')
    os.makedirs(tmpdir, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=tmpdir, delete=False) as f:
        f.write(contents.encode('utf-8'))
        return f.name


def windows_escape(args):
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
    return final_cmdline


def format_cmdline(
        driver, instrumentation, mutator, iterations,
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
    return windows_escape(args)
