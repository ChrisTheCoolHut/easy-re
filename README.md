# Concolic Execution for low point reverse engineering problems

 - python easy_re.py -h
 - usage: easy_re.py [-h] [-f FILE] [-s START] [-e END] [-a]

# Quick Concolic Analysis

```
 optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Binary File
  -s START, --start START
                        Where to start analyzing from
  -e END, --end END     Where to stop analyzing
  -a, --args            Solve for a symbolic arg (optional)
  -x AVOID, --avoid AVOID
                        Where to avoid analysis, eg 0x12345678,0x12345678

```

# Install
```
pip install easy_re
```

# Solve for STDIN in a program
 -  -f for the filename
 -  -s for the address to start at
 -  -e for the address to end at

 ```
python easy_re.py -f crackme0x04 -s 0x08048509 -e 0x080484ef
```

# Solve for ARGs in a program
 -  -f for the filename
 -  -s for the address to start at
 -  -e for the address to end at
 -  -a for arg solves

 ```
python easy_re.py -f baby2 -s 0x004005b6 -e 0x4031a3 -a
```

# Install Angr

```
sudo apt-get install python-pip python-dev build-essential
sudo pip install virtualenv virtualenvwrapper
sudo pip install --upgrade pip
```

Setup virtualenwrapper in ~/.bashrc

```
printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' \
'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

source ~/.bashrc
```

Install angr

```
mkvirtualenv angr

workon angr

pip install angr
```

 - Now whenever you want to work on angr, just run ```workon angr```
 - That will put you in a virtual python environment that can run the easy_re script
