#!/usr/bin/python3

from __future__ import annotations

import requests
import json

from typing import Any

from .abstractgenerator import AbstractMISPObjectGenerator

# Original sourcecode: https://github.com/hayk57/MISP_registration_check


class VehicleObject(AbstractMISPObjectGenerator):
    '''Vehicle object generator out of regcheck.org.uk'''

    country_urls: dict[str, str] = {
        'fr': "http://www.regcheck.org.uk/api/reg.asmx/CheckFrance",
        'es': "http://www.regcheck.org.uk/api/reg.asmx/CheckSpain",
        'uk': "http://www.regcheck.org.uk/api/reg.asmx/Check"
    }

    def __init__(self, country: str, registration: str, username: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('vehicle', **kwargs)
        if country not in self.country_urls:
            raise ValueError(f"Country {country} not supportet, must be one of {self.country_urls.keys()}")
        self._country = country
        self._registration = registration
        self._username = username
        self._report = self._query()
        self.generate_attributes()

    @property
    def report(self) -> dict[str, Any]:
        return self._report

    def generate_attributes(self) -> None:
        carDescription = self._report["Description"]
        carMake = self._report["CarMake"]["CurrentTextValue"]
        carModel = self._report["CarModel"]["CurrentTextValue"]
        ImageUrl = self._report["ImageUrl"]
        IndicativeValue = ''
        if (self._country == "fr"):
            IndicativeValue = self._report["IndicativeValue"]["CurrentTextValue"]
            # BodyStyle = vehicleJson["BodyStyle"]["CurrentTextValue"]
            # RegistrationDate = vehicleJson["RegistrationDate"]
            VIN = self._report["ExtendedData"]["numSerieMoteur"]
            gearbox = self._report["ExtendedData"]["boiteDeVitesse"]
            dynoHP = self._report["ExtendedData"]["puissanceDyn"]
            firstRegistration = self._report["ExtendedData"]["datePremiereMiseCirculation"]

            self.add_attribute('dyno-power', type='text', value=dynoHP)
            self.add_attribute('gearbox', type='text', value=gearbox)

        if (self._country == "es"):
            IndicativeValue = self._report["IndicativePrice"]

        if (self._country == "es" or self._country == "uk"):
            firstRegistration = self._report["RegistrationYear"]
            VIN = self._report["VehicleIdentificationNumber"]

        self.add_attribute('description', type='text', value=carDescription)
        self.add_attribute('make', type='text', value=carMake)
        self.add_attribute('model', type='text', value=carModel)
        self.add_attribute('vin', type='text', value=VIN)
        self.add_attribute('license-plate-number', type='text', value=self._registration)

        self.add_attribute('indicative-value', type='text', value=IndicativeValue)

        self.add_attribute('date-first-registration', type='text', value=firstRegistration)
        self.add_attribute('image-url', type='text', value=ImageUrl)

    def _query(self) -> dict[str, Any]:
        payload = f"RegistrationNumber={self._registration}&username={self._username}"
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'cache-control': "no-cache",
        }

        response = requests.request("POST", self.country_urls[self._country], data=payload, headers=headers)
        # FIXME: Clean that up.
        for item in response.text.split("</vehicleJson>"):
            if "<vehicleJson>" in item:
                responseJson = item[item.find("<vehicleJson>") + len("<vehicleJson>"):]

        return json.loads(responseJson)
