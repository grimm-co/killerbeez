.PHONY=all clean
TYPESETTER=pdflatex

all: killerbeez.pdf

clean:
	rm -f *.out *.aux *.toc *.out *.log *.pdf

killerbeez.pdf: killerbeez.tex packages.tex introduction.tex references.tex \
		implementation.tex overview.tex future_work.tex \
		background.tex related_work.tex
	${TYPESETTER} killerbeez.tex
	${TYPESETTER} killerbeez.tex  # do it twice for the bibliography
