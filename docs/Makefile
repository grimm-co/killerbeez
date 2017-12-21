.PHONY=all clean
TYPESETTER=pdflatex

all: api.pdf

clean:
	rm -f *.out *.aux *.toc *.out *.log *.pdf

api.pdf: api.tex api_mutator.tex defines.tex
	${TYPESETTER} api.tex # first time for the ToC
	${TYPESETTER} api.tex # second time for the real deal
