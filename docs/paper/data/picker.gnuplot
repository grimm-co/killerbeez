set terminal pngcairo  background "#ffffff" enhanced fontscale 1.0 dashlength 2
set output '../picker.png'

set title "Detected Non-Detemrinistic Basic Block Transitions in\nWindows Media Player Libraries"

set xlabel '{/Helvetica-Oblique Number of Executions}' font 'arial,10'
set ylabel '{/Helvetica-Oblique Non-deterministic Basic Block Transitions Detected}' font 'arial,10'

set linetype 1 dt 1
set style line 1 lt 1 lw 2
set linetype 2 dt 2
set style line 2 lt 2 lw 2
set linetype 3 dt 3
set style line 3 lt 3 lw 3
set linetype 4 dt 4
set style line 4 lt 4 lw 2

plot "data/AudioSes.dll" title 'AudioSes.dll' with lines ls 2, \
		"data/MFPlat.dll" title 'MFPlat.dll' with lines ls 1, \
		"data/MSIMG32.dll" title 'MSIMG32.dll' with lines ls 3, \
		"data/WindowsCodecs.dll" title 'WindowsCodecs.dll' with lines ls 4
