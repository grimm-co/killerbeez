rem Dependencies:
rem git https://git-scm.com/download/win
rem wget http://gnuwin32.sourceforge.net/packages/wget.htm
rem cmake https://cmake.org/download/
rem unzip ?

mkdir C:\killerbeez
cd \killerbeez

git clone https://github.com/grimm-co/killerbeez.git
git clone https://github.com/grimm-co/killerbeez-mutators.git
git clone https://github.com/grimm-co/killerbeez-utils.git
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_6_2_0/DynamoRIO-Windows-6.2.0-2.zip
unzip DynamoRIO-Windows-6.2.0-2.zip
mv DynamoRIO-Windows-6.2.0-2 dynamorio
cd killerbeez
mkdir build
cd build
cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build .

