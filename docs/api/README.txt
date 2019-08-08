# API Documentation

This directory contains all the documentation for the KILLERBEEZ API.  This 
means it includes the documentation for the mutator API, even though the
mutators are kept in a separate repository.  Mutator specific documentation,
however, is kept in the mutator's repository.

# Building

The included Makefile can be used to build the api.pdf documentation by running
the command `make` from this directory. The documentation is written in
[LaTeX](https://www.latex-project.org/) and uses `pdflatex` to compile.

On Ubuntu a working LaTeX environment can be setup with the following command:
```
sudo apt install okular texlive texlive-full texinfo texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended latex2rtf pandoc
```

On macOS, a working LaTeX environment can be setup using the
[MacTeX package](https://tug.org/mactex/mactex-download.html) or via homebrew.

On Windows, a working LaTeX environment can be setup via the
[MiKTeX project](https://miktex.org/).
