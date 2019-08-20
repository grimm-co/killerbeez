REM Meant to be run by CI from the root directory of one of the repos
REM Usage: cd Killerbeez; tools\update_repos

if "%KILLERBEEZ_URL%" == "" (
  set KILLERBEEZ_URL=https://github.com/grimm-co/Killerbeez.git
)

call :update %KILLERBEEZ_URL% || exit /b 1

exit /b 0

:update
set repourl=%1
for %%d in ("%repourl%") do set repopath=%%~nd

if "%repopath%" == "%CI_PROJECT_NAME%" (
  exit /b 0
)

if exist %repopath% (
  cd "%repopath%"
  git fetch || exit /b 1
  git submodule update --init || exit /b 1
) else (
  git clone --recursive "%repourl%" || exit /b 1
  cd "%repopath%"
)

if not "%CI_COMMIT_REF_NAME%" == "" (
  echo Checking out origin/%CI_COMMIT_REF_NAME%
  git checkout origin/%CI_COMMIT_REF_NAME%
  if ERRORLEVEL 1 (
    git checkout master
    git pull
  )
)

cd ..
exit /b 0
