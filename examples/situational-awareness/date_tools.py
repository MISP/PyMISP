#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse


class DateError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# ############### Date Tools ################

def dateInRange(datetimeTested, begin=None, end=None):
    if begin is None:
        begin = datetime(1970, 1, 1)
    if end is None:
        end = datetime.now()
    return begin <= datetimeTested <= end


def toDatetime(date):
    return parse(date)


def datetimeToString(datetime, formatstring):
    return datetime.strftime(formatstring)


def checkDateConsistancy(begindate, enddate, lastdate):
    if begindate is not None and enddate is not None:
        if begindate > enddate:
            raise DateError('begindate ({}) cannot be after enddate ({})'.format(begindate, enddate))

    if enddate is not None:
        if toDatetime(enddate) < lastdate:
            raise DateError('enddate ({}) cannot be before lastdate ({})'.format(enddate, lastdate))

    if begindate is not None:
        if toDatetime(begindate) > datetime.now():
            raise DateError('begindate ({}) cannot be after today ({})'.format(begindate, datetime.now().date()))


def setBegindate(begindate, lastdate):
    return max(begindate, lastdate)


def setEnddate(enddate):
    return min(enddate, datetime.now())


def getLastdate(last):
    return (datetime.now() - timedelta(days=int(last))).replace(hour=0, minute=0, second=0, microsecond=0)


def getNDaysBefore(date, days):
    return (date - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)


def getToday():
    return (datetime.now()).replace(hour=0, minute=0, second=0, microsecond=0)


def days_between(date_1, date_2):
    return abs((date_2 - date_1).days)
