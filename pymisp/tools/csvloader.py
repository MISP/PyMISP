#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path

import csv
from pymisp import MISPObject


class CSVLoader():

    def __init__(self, template_name: str, csv_path: Path,
                 fieldnames: list[str] | None = None, has_fieldnames: bool=False,
                 delimiter: str = ',', quotechar: str = '"') -> None:
        self.template_name = template_name
        self.delimiter = delimiter
        self.quotechar = quotechar
        self.csv_path = csv_path
        self.fieldnames = []
        if fieldnames:
            self.fieldnames = [f.strip() for f in fieldnames]
        if not self.fieldnames:
            # If the user doesn't pass fieldnames, they must be in the CSV.
            self.has_fieldnames = True
        else:
            self.has_fieldnames = has_fieldnames

    def load(self) -> list[MISPObject]:

        objects = []

        with open(self.csv_path, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=self.delimiter, quotechar=self.quotechar)
            if self.has_fieldnames:
                # The file has fieldnames, we either ignore it, or use them as object-relation
                fieldnames = [f.strip() for f in reader.__next__()]
                if not self.fieldnames:
                    self.fieldnames = fieldnames

            if not self.fieldnames:
                raise Exception('No fieldnames, impossible to create objects.')

            # Check if the CSV file has a header, and if it matches with the object template
            tmp_object = MISPObject(self.template_name)

            if not tmp_object._definition or not tmp_object._definition['attributes']:
                raise Exception(f'Unable to find the object template ({self.template_name}), impossible to create objects.')
            allowed_fieldnames = list(tmp_object._definition['attributes'].keys())
            for fieldname in self.fieldnames:
                if fieldname not in allowed_fieldnames:
                    raise Exception(f'{fieldname} is not a valid object relation for {self.template_name}: {allowed_fieldnames}')

            for row in reader:
                tmp_object = MISPObject(self.template_name)
                has_attribute = False
                for object_relation, value in zip(self.fieldnames, row):
                    if value:
                        has_attribute = True
                        tmp_object.add_attribute(object_relation, value=value)
                if has_attribute:
                    objects.append(tmp_object)
        return objects
