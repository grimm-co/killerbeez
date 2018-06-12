.PHONY=all clean
TYPESETTER=pdflatex

all: api.pdf

clean:
	rm -f *.out *.aux *.toc *.out *.log *.pdf

api.pdf: api.tex defines.tex api_mutator.tex api_driver.tex \
		api_instrumentation.tex coverpage.tex
	${TYPESETTER} api.tex # first time for the ToC
	${TYPESETTER} api.tex # second time for the real deal
