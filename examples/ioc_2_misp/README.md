### Description

Python script for ioc import to misp

### requires

> python 2.7  
> PyMISP  
> BeautifulSoup (apt-get install python-bs4 python-lxml)

### Usage

```bash
python ioc2misp.py -i myioc -t "tag:mytag='sample','tag:other='foo'"
```

```bash
time find /iocsample -type f|while read line ;do python ioc2misp.py -i ${line};done
```

### Conf

 * rename keys.py.sample as keys.py
 * add your url and api key in keys.py
 * use command in terminal
