# Client/Server Operation using BOINC

## Installation

### Server (Tested on Ubuntu 16.04)
1. Install required software

	```
    sudo apt update && sudo apt install git m4 pkg-config autoconf libtool \
      libssl-dev libmysqlclient-dev libcurl4-openssl-dev python apache2 \
      mysql-server python-mysqldb haveged php libapache2-mod-php php-mysql \
      php-xml-parser curl python-requests python-virtualenv unzip
	```
	* You will be asked to set a password for mysql root user
2. Get code
	```
    sudo mkdir /usr/local/killerbeez
    sudo chown $USER /usr/local/killerbeez
    sudo chmod a+rx /usr/local/killerbeez
    umask 0022
    cd /usr/local/killerbeez
    git clone --recursive https://github.com/grimm-co/killerbeez.git
	```
3. Build code
	```
  cd killerbeez/server/boinc
  ./_autosetup
  ./configure --disable-client --disable-manager
  make
	```
4. User permissions
	```
  sudo useradd -m -s /bin/bash boincadm
  sudo usermod -a -G boincadm www-data
  sudo -u boincadm sh -c 'echo umask 0007 >> /home/boincadm/.bashrc'
  sudo sh -c 'echo umask 0007 >> /etc/apache2/envvars'
  sudo chgrp boincadm /usr/local/killerbeez
  sudo chmod g+w /usr/local/killerbeez
	```
  * Note: the new user doesn't have sudo access, so continue using your normal
    account for the remaining instructions except when indicated.
5. MySQL setup (make sure to select your own password)
  ```
  mysql -u root -p
  mysql> CREATE USER 'killerbeez'@'localhost' IDENTIFIED BY '<password here>';
  mysql> GRANT ALL ON killerbeez.* to 'killerbeez'@'localhost';
  ```
  ```
  sudo sh -c 'echo sql_mode="ONLY_FULL_GROUP_BY,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION" >> /etc/mysql/mysql.conf.d/mysqld.cnf'
  sudo systemctl restart mysql
  ```
6. Apache setup
  ```
  sudo a2enmod cgi
  sudo systemctl restart apache2
  ```
7. Project setup (run as the boincadm user)
    1. First, open a shell as the boincadm user for the rest of this step

        ```
        sudo -i -u boincadm
        ```
    2. Determine a URL that points to this server. If accessed in a browser,
       this URL should display the default Apache "It works!" page. If this
       will  be a public instance, take a look at
       [these guidelines](https://boinc.berkeley.edu/trac/wiki/MasterUrl#ChoosingaprojectURL).
       * `export BOINC_URL=<this url>`
    3. Create the BOINC project for Killerbeez

        ```
        cd /usr/local/killerbeez/killerbeez/server/boinc
        tools/make_project --url_base $BOINC_URL \
          --db_user killerbeez --db_pass '<password here>' killerbeez
        ```
        * Enter Y at the prompt.
    4. Set up cron, load platforms into the database, and set a password to
       access the admin UI
        ```
        cd ~/projects/killerbeez
        crontab killerbeez.cronjob
        bin/xadd
        htpasswd -c html/ops/.htpasswd <admin username>
        ```
    5. Edit `html/project/project.inc` to set PROJECT and COPYRIGHT_HOLDER
       correctly
    6. Install killerbeez-specific files:
        ```
        cp /usr/local/killerbeez/killerbeez/server/*.py bin
        cp -r /usr/local/killerbeez/killerbeez/server/skel .
        ```
    7. Download the latest
       [killerbeez-x64.zip](https://github.com/grimm-co/killerbeez/releases) and
       place it in the `skel/windows_x86_64` directory
    8. Extract the wrapper binary (or see the [build instructions](#wrapper) to
       build your own copy):
        ```
        unzip -j -d skel/windows_x86_64 skel/windows_x86_64/killerbeez-x64.zip \
          '*wrapper_26014_windows_x86_64.exe'
        ```
    6. Enable the project
        ```
        bin/start
        ```
    7. Done running as boincadm

        ```
        exit
        ```
8. Install Apache config for project

    ```
    sudo cp /home/boincadm/projects/killerbeez/killerbeez.httpd.conf /etc/apache2/sites-available/killerbeez.conf
    sudo sed -i -e '/Order /d' -e 's/Deny from all/Require all denied/' \
      -e 's/Allow from all/Require all granted/' \
      /etc/apache2/sites-available/killerbeez.conf
    sudo a2ensite killerbeez
    sudo systemctl reload apache2
    ```

10. Start the Killerbeez API server
    ```
    sudo -i -u boincadm
    cd /usr/local/killerbeez
    virtualenv -ppython3 killerbeez-venv
    source killerbeez-venv/bin/activate
    cd /usr/local/killerbeez/killerbeez/python/manager
    pip install -r requirements.txt
    python server.py -create  # Remove -create if restarting server
    ```
    This will start up the server on port 5000. In the instructions below, we
    will call the URL pointing to this port `$API_URL`.
    
### Client - Windows 10 x64 only for now
1. Create an account via BOINC webpage (`$BOINC_URL/killerbeez/create_account_form.php`)
2. GUI instructions to add project:
  1. Go to Project > Join on website
  2. If client not installed, install it
  3. Select "Add project" in GUI
  4. Enter project URL from webpage
  5. Enter email address and password of the account you registered in step 1
3. Command-line instructions to add project:
  1. Go to Project > Join on website
  2. If client not installed, install it (e.g., `apt install boinc-client`)
  3. `boinccmd --lookup_account <project url> <email address> <password>`
    * Returns account key
  4. `boinccmd --project_attach <project url> <account key>`

## Administration

### Add a target
Killerbeez jobs have a "target", which represents a target program running on a
certain platform. BOINC needs to be told about these targets, and the platforms
they can run on. The [add_target.py](../server/add_target.py) tool will create a
BOINC "app" for each target/platform combination. These can be customized to
install a new application, but the default configuration will allow fuzzing
anything that is installed on client machines already, such as Windows Media
Player.

1. Create the target

    ```
    bin/add_target.py <target> <platform> [<platform> ...]
    ```
    * Example: `bin/add_target.py wmp windows_x86_64`
2. If you need any additional files in this app, put them in the app dir
   (`apps/<target>_<platform>/1/<platform>`)
3. Finalize the app creation

    ```
    bin/update_versions
    ```

### Submit job
Customize the [boinc_submit.py](../server/boinc_submit.py) script for your
desired job by changing the constants at the top, and the job parameters in the
requests. The constants are:
* `PROJECT` - The URL for the Killerbeez API (`$API_URL`)
* `SEED` - A string to be used as the contents of the seed file

Run the script, and it will print out the ID of the submitted job. 

### View job results
The results of a job can be accessed via the killerbeez API. Let `$JOB_ID`
be the ID of the job of interest:
```
curl $API_URL/api/job/$JOB_ID/results
```
For example:
```
$ curl http://localhost:5000/api/job/37/results                                                                                       
[{"result_type": "crash", "repro_file": "3fb/38D1F16F84B07DBF6B29861BD7464ABA", "job_id": 37, "result_id": 1}, {"result_type": "crash", "repro_file": "235/97A596BE0B77EF1B6899503300B205FE", "job_id": 37, "result_id": 2}]
```
The output is a JSON list of all the job's results. Each result is a JSON
object, in which the result_type describes why this result is interesting
(crash? hang? new_path?), and the repro_file is the path of a file with the
input that caused the crash, hang, or new path. To retrieve the crashing input:
```
curl $BOINC_URL/killerbeez/download/$repro_file
```
For example:
```
$ curl http://localhost:80/killerbeez/download/3fb/38D1F16F84B07DBF6B29861BD7464ABA
-215005474723783
```
You may be interested to know what seed file these results were mutated from.
The path of the seed file is available in the job information:
```
curl $API_URL/api/job/$JOB_ID
```
For example:
```
$ curl http://localhost:5000/api/job/37
{"mutator": null, "end_time": null, "status": "completed", "input_ids": [], "instrumentation_type": null, "seed_file": "ab/jf_2f79d50c5c10004b755b4622555e99f5", "job_type": null, "mutator_state": null, "driver": null, "assign_time": null, "job_id": 37}
```
When jobs are submitted automatically, the seed file may be the result of some
other job, in which case it's possible to find the job that produced it by
searching results by repro_file:
```
curl $API_URL/api/results?repro_file=$repro_file
```
For example:
```
$ curl http://localhost:5000/api/results?repro_file=235/97A596BE0B77EF1B6899503300B205FE
[{"result_type": "crash", "repro_file": "235/97A596BE0B77EF1B6899503300B205FE", "job_id": 37, "result_id": 2}]
```
This gives you the job ID of the job that produced the file, allowing you to
trace its ancestry.

### Set up account with administrator access
This step is only needed if you are going to create an account that will submit
jobs directly to BOINC (see next section). You do not need administrator access
to submit jobs via the Killerbeez API server.
1. Administrator must register an account via BOINC webpage (`$BOINC_URL/killerbeez/create_account_form.php`)
2. Log into site and go to Project > Account to find User ID
3. On server:

    ```
    sudo -i -u boincadm
    cd ~/projects/killerbeez
    bin/manage_privileges grant <user id> all`
    ```

### Set up account with direct BOINC job submission privileges
You only need to do this if you want to submit jobs directly to BOINC (most
likely for testing). Submitting jobs via the Killerbeez API server does not
require this.
To perform these steps you must have administrator access (see previous
section). However, as an administrator you can grant job submission privileges
to any account, administrator or otherwise.
1. Go to `$BOINC_URL/killerbeez/manage_project.php`
2. Click name of the user to grant privileges to
3. Select "All apps"
4. Click "Ok".

## Optional build instructions

### Wrapper
The BOINC [wrapper](https://boinc.berkeley.edu/trac/wiki/WrapperApp) is an
adapter that lets programs be run unmodified under the BOINC client. Our usage
of the wrapper requires features and bugfixes that are more recent than the last
released wrapper binary. Our binary release inlcudes a compiled copy of the
wrapper, as described above, but you can build your own with the following
steps:
1. On a Windows machine, install [git](https://git-scm.com/downloads) and
   [Visual Studio Community 2013](https://visualstudio.microsoft.com/vs/older-downloads/)
2. Start Git Bash and clone the [BOINC repository](https://github.com/BOINC/boinc)
3. Open `win_build\boinc_vs2013.sln` from the cloned repo in Visual Studio 2013
4. Click the `wrapper` project in the Solution Explorer
5. Select `x64` from the Platforms drop-down in the toolbar, and `Release`
   from the Configurations drop-down next to it.
6. From the `BUILD` menu, select `Build wrapper`
7. The compiled binary should be in
   `win_build\Build\x64\Release\wrapper_26014_windows_x86_64.exe`
8. Drop this binary into the `/home/boincadm/projects/killerbeez/skel/windows_x86_64`
   directory on your killerbeez server
