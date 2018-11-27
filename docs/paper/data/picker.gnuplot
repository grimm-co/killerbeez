set style line 1 linecolor rgb "#0060ad' linetype 1 linewidth 2 pointtype 3 pointsize 1.5
set terminal png enhanced background rgb 'white'
set xlabel '{/Helvetica-Oblique Number of Executions}'
set ylabel '{/Helvetica-Oblique Non-deterministic Basic Block Transitions Detected}'
set output '../picker.png'
plot "data/AudioSes.DLL" title 'AudioSes.dll' with lines, \
		"data/MFPlat.DLL" title 'MFPlat.dll' with lines, \
		"data/MSIMG32.dll" title 'MSIMG32.dll' with lines, \
		"data/WindowsCodecs.dll" title 'WindowsCodecs.dll' with lines
