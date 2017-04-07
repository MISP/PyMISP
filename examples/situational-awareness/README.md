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

* tags\_to\_graphs.py is a script that will generate several plots to visualise tags distribution.
    * The studied _period_ can be either the 7, 28 or 360 last days
    * _accuracy_ allows to get smallers splits of data instead of the default values
    * _order_ define the accuracy of the curve fitting. Default value is 3
    * It will generate two plots comparing all the tags:
		* tags_repartition_plot that present the raw data
		* tags_repartition_trend_plot that present the general evolution for each tag
	* Then each taxonomies will be represented in three plots:
        * Raw datas: in "plot" folder, named with the name of the corresponding taxonomy
        * Trend: in "plot" folder, named _taxonomy_\_trend. general evolution of the data (linear fitting, curve fitting at order 1)
        * Curve fitting: in "plotlib" folder, name as the taxonomy it presents.
	* In order to visualize the last plots, a html file is also generated automaticaly (might be improved in the future)

:warning: These scripts are not time optimised

## Requierements

* [Pygal](https://github.com/Kozea/pygal/)
* [Matplotlib](https://github.com/matplotlib/matplotlib)
* [Pandas](https://github.com/pandas-dev/pandas)
* [SciPy](https://github.com/scipy/scipy)
* [PyTaxonomies](https://github.com/MISP/PyTaxonomies)
* [Python3-tk](https://github.com/python-git/python/blob/master/Lib/lib-tk/Tkinter.py)

