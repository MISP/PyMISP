## Explanation

* treemap.py is a script that will generate an interactive svg (attribute\_treemap.svg) containing a treepmap representing the distribution of attributes in a sample (data) fetched from the instance using "last" or "searchall" examples.
* It will also generate a html document with a table (attribute\_table.html) containing count for each type of attribute.
* test\_attribute\_treemap.html is a quick page made to visualize both treemap and table at the same time.

* tags\_count.py is a script that count the number of occurences of every tags in a fetched sample of Events in a given period of time.
* tag\_search.py is a script that count the number of occurences of a given tag  in a fetched sample of Events in a given period of time.
    * Events will be fetched from _days_ days ago to today.
    * _begindate_ is the beginning of the studied period. If it is later than today, an error will be raised.
    * _enddate_ is the end of the studied period. If it is earlier than _begindate_, an error will be raised.
    * tag\_search.py allows research for multiple tags is possible by separating each tag by the | symbol.
    * Partial research is also possible with tag\_search.py. For instance, search for "ransom" will also return tags containin "ransomware".

:warning: These scripts are not time optimised

## Requierements

* [Pygal](https://github.com/Kozea/pygal/)
