from __future__ import annotations

from datetime import timezone, datetime, date
import copy
import os
import base64
import sys
from io import BytesIO, BufferedIOBase, TextIOBase
from zipfile import ZipFile
import uuid
from uuid import UUID
from collections import defaultdict
import logging
import hashlib
from pathlib import Path
from typing import IO, Any, Sequence
import warnings

try:
    # orjson is optional dependency that speedups parsing and encoding JSON
    import orjson as json  # type: ignore
except ImportError:
    import json

from .abstract import AbstractMISP, MISPTag
from .exceptions import (NewNoteError, NewOpinionError, NewRelationshipError, UnknownMISPObjectTemplate, InvalidMISPGalaxy, InvalidMISPAttribute,
                         InvalidMISPObject, InvalidMISPObjectAttribute, PyMISPError, NewEventError, NewAttributeError, NewEventReportError,
                         NewGalaxyClusterError, NewGalaxyClusterRelationError, NewAnalystDataError)

logger = logging.getLogger('pymisp')


class AnalystDataBehaviorMixin(AbstractMISP):

    # NOTE: edited here must be the property of Abstract MISP

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        self.uuid: str  # Created in the child class
        self._analyst_data_object_type: str  # Must be defined in the child class
        self.Note: list[MISPNote] = []
        self.Opinion: list[MISPOpinion] = []
        self.Relationship: list[MISPRelationship] = []

    @property
    def analyst_data_object_type(self) -> str:
        return self._analyst_data_object_type

    @property
    def notes(self) -> list[MISPNote]:
        return self.Note

    @property
    def opinions(self) -> list[MISPOpinion]:
        return self.Opinion

    @property
    def relationships(self) -> list[MISPRelationship]:
        return self.Relationship

    def add_note(self, note: str, language: str | None = None, **kwargs) -> MISPNote:  # type: ignore[no-untyped-def]
        the_note = MISPNote()
        the_note.from_dict(note=note, language=language,
                           object_uuid=self.uuid, object_type=self.analyst_data_object_type,
                           **kwargs)
        self.notes.append(the_note)
        self.edited = True
        return the_note

    def add_opinion(self, opinion: int, comment: str | None = None, **kwargs) -> MISPNote:  # type: ignore[no-untyped-def]
        the_opinion = MISPOpinion()
        the_opinion.from_dict(opinion=opinion, comment=comment,
                              object_uuid=self.uuid, object_type=self.analyst_data_object_type,
                              **kwargs)
        self.opinions.append(the_opinion)
        self.edited = True
        return the_opinion

    def add_relationship(self, related_object_type: AbstractMISP | str, related_object_uuid: str | None, relationship_type: str, **kwargs) -> MISPNote:  # type: ignore[no-untyped-def]
        the_relationship = MISPRelationship()
        the_relationship.from_dict(related_object_type=related_object_type, related_object_uuid=related_object_uuid,
                                   relationship_type=relationship_type,
                                   object_uuid=self.uuid, object_type=self.analyst_data_object_type,
                                   **kwargs)
        self.relationships.append(the_relationship)
        self.edited = True
        return the_relationship

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        # These members need a fully initialized class to be loaded properly
        notes = kwargs.pop('Note', [])
        opinions = kwargs.pop('Opinion', [])
        relationships = kwargs.pop('Relationship', [])
        super().from_dict(**kwargs)
        for note in notes:
            note.pop('object_uuid', None)
            note.pop('object_type', None)
            self.add_note(**note)
        for opinion in opinions:
            opinion.pop('object_uuid', None)
            opinion.pop('object_type', None)
            self.add_opinion(**opinion)
        for relationship in relationships:
            relationship.pop('object_uuid', None)
            relationship.pop('object_type', None)
            self.add_relationship(**relationship)


try:
    from dateutil.parser import parse
except ImportError:
    logger.exception("Cannot import dateutil")


def _make_datetime(value: int | float | str | datetime | date) -> datetime:
    if isinstance(value, (int, float)):
        # Timestamp
        value = datetime.fromtimestamp(value)
    elif isinstance(value, str):
        try:
            # faster
            value = datetime.fromisoformat(value)
        except Exception:
            value = parse(value)  # type: ignore[arg-type]
    elif isinstance(value, datetime):
        pass
    elif isinstance(value, date):  # NOTE: date has to be *after* datetime, or it will be overwritten
        value = datetime.combine(value, datetime.min.time())
    else:
        raise PyMISPError(f'Invalid format for {value}: {type(value)}.')

    if not value.tzinfo:
        # set localtimezone if not present
        value = value.astimezone()
    return value


def make_bool(value: bool | int | str | dict[str, Any] | list[Any] | None) -> bool:
    """Converts the supplied value to a boolean.

    :param value: Value to interpret as a boolean.  An empty string, dict
        or list is False; value None is also False.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if not value:  # None, 0, '', {}, []
        return False

    if isinstance(value, str):
        if value == '0':
            return False
        return True
    else:
        raise PyMISPError(f'Unable to convert {value} to a boolean.')


class MISPOrganisation(AbstractMISP):

    _fields_for_feed: set[str] = {'name', 'uuid'}

    def __init__(self) -> None:
        super().__init__()
        self.id: int
        self.name: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Organisation' in kwargs:
            kwargs = kwargs['Organisation']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return f'<{self.__class__.__name__}(type={self.name})'
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPSharingGroupOrg(AbstractMISP):
    _fields_for_feed: set[str] = {'extend', 'Organisation'}

    def __init__(self) -> None:
        super().__init__()
        self.extend: bool
        self.Organisation: MISPOrganisation

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'SharingGroupOrg' in kwargs:
            kwargs = kwargs['SharingGroupOrg']
        if 'Organisation' in kwargs:
            self.Organisation = MISPOrganisation()
            self.Organisation.from_dict(**kwargs.pop('Organisation'))
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'Organisation') and hasattr(self, 'extend'):
            return f'<{self.__class__.__name__}(Org={self.Organisation.name}, extend={self.extend})'
        return f'<{self.__class__.__name__}(NotInitialized)'

    def _to_feed(self) -> dict[str, Any]:
        to_return = super()._to_feed()
        to_return['Organisation'] = self.Organisation._to_feed()
        return to_return


class MISPSharingGroup(AbstractMISP):
    _fields_for_feed: set[str] = {'uuid', 'name', 'roaming', 'created', 'organisation_uuid', 'Organisation', 'SharingGroupOrg', 'SharingGroupServer'}

    def __init__(self) -> None:
        super().__init__()
        self.name: str
        self.SharingGroupOrg: list[MISPSharingGroupOrg] = []

    @property
    def sgorgs(self) -> list[MISPSharingGroupOrg]:
        return self.SharingGroupOrg

    @sgorgs.setter
    def sgorgs(self, sgorgs: list[MISPSharingGroupOrg]) -> None:
        if all(isinstance(x, MISPSharingGroupOrg) for x in sgorgs):
            self.SharingGroupOrg = sgorgs
        else:
            raise PyMISPError('All the attributes have to be of type MISPSharingGroupOrg.')

    def add_sgorg(self, sgorg: dict[str, Any]) -> MISPSharingGroupOrg:
        misp_sgorg = MISPSharingGroupOrg()
        misp_sgorg.from_dict(**sgorg)
        self.SharingGroupOrg.append(misp_sgorg)
        return misp_sgorg

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'SharingGroupOrg' in kwargs:
            [self.add_sgorg(sgorg) for sgorg in kwargs.pop('SharingGroupOrg')]
        if 'SharingGroup' in kwargs:
            kwargs = kwargs['SharingGroup']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return f'<{self.__class__.__name__}(name={self.name})>'
        return f'<{self.__class__.__name__}(NotInitialized)>'

    def _to_feed(self) -> dict[str, Any]:
        to_return = super()._to_feed()
        to_return['SharingGroupOrg'] = [sgorg._to_feed() for sgorg in self.SharingGroupOrg]
        to_return['Organisation'].pop('id', None)
        for server in to_return['SharingGroupServer']:
            server.pop('id', None)
            server.pop('sharing_group_id', None)
            server.pop('server_id', None)
            server['Server'].pop('id', None)
        return to_return


class MISPShadowAttribute(AbstractMISP):

    def __init__(self) -> None:
        super().__init__()
        self.type: str
        self.value: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'ShadowAttribute' in kwargs:
            kwargs = kwargs['ShadowAttribute']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'value'):
            return f'<{self.__class__.__name__}(type={self.type}, value={self.value})'
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPSighting(AbstractMISP):

    def __init__(self) -> None:
        super().__init__()
        self.id: int
        self.value: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """Initialize the MISPSighting from a dictionary

        :param value: Value of the attribute the sighting is related too. Pushing this object
            will update the sighting count of each attribute with this value on the instance.
        :param uuid: UUID of the attribute to update
        :param id: ID of the attriute to update
        :param source: Source of the sighting
        :param type: Type of the sighting
        :param timestamp: Timestamp associated to the sighting
        """
        if 'Sighting' in kwargs:
            kwargs = kwargs['Sighting']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(value={self.value})'.format(self=self)
        if hasattr(self, 'id'):
            return '<{self.__class__.__name__}(id={self.id})'.format(self=self)
        if hasattr(self, 'uuid'):
            return '<{self.__class__.__name__}(uuid={self.uuid})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPAttribute(AnalystDataBehaviorMixin):
    _fields_for_feed: set[str] = {'uuid', 'value', 'category', 'type', 'comment', 'data',
                                  'deleted', 'timestamp', 'to_ids', 'disable_correlation',
                                  'first_seen', 'last_seen'}

    _analyst_data_object_type = 'Attribute'

    def __init__(self, describe_types: dict[str, Any] | None = None, strict: bool = False):
        """Represents an Attribute

        :param describe_types: Use it if you want to overwrite the default describeTypes.json file (you don't)
        :param strict: If false, fallback to sane defaults for the attribute type if the ones passed by the user are incorrect
        """
        super().__init__()
        if describe_types:
            self.describe_types: dict[str, Any] = describe_types
        self.__categories: list[str] = self.describe_types['categories']
        self.__category_type_mapping: dict[str, list[str]] = self.describe_types['category_type_mappings']
        self.__sane_default: dict[str, dict[str, str | int]] = self.describe_types['sane_defaults']
        self.__strict: bool = strict
        self.data: BytesIO | None = None
        self.first_seen: datetime
        self.last_seen: datetime
        self.uuid: str = str(uuid.uuid4())
        self.ShadowAttribute: list[MISPShadowAttribute] = []
        self.SharingGroup: MISPSharingGroup
        self.Sighting: list[MISPSighting] = []
        self.Tag: list[MISPTag] = []
        self.Galaxy: list[MISPGalaxy] = []

        self.expand: str
        self.timestamp: float | int | datetime

        # For search
        self.Event: MISPEvent
        self.RelatedAttribute: list[MISPAttribute]

        # For malware sample
        self._malware_binary: BytesIO | None

    def add_tag(self, tag: str | MISPTag | dict[str, Any] | None = None, **kwargs) -> MISPTag:  # type: ignore[no-untyped-def]
        return super()._add_tag(tag, **kwargs)

    @property
    def tags(self) -> list[MISPTag]:
        """Returns a list of tags associated to this Attribute"""
        return self.Tag

    @tags.setter
    def tags(self, tags: list[MISPTag]) -> None:
        """Set a list of prepared MISPTag."""
        super()._set_tags(tags)

    def add_galaxy(self, galaxy: MISPGalaxy | dict[str, Any] | None = None, **kwargs) -> MISPGalaxy:  # type: ignore[no-untyped-def]
        """Add a galaxy to the Attribute, either by passing a MISPGalaxy or a dictionary"""
        if isinstance(galaxy, MISPGalaxy):
            self.galaxies.append(galaxy)
            return galaxy
        if isinstance(galaxy, dict):
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**galaxy)
        elif kwargs:
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**kwargs)
        else:
            raise InvalidMISPGalaxy("A Galaxy to add to an existing Attribute needs to be either a MISPGalaxy or a plain python dictionary")
        self.galaxies.append(misp_galaxy)
        return misp_galaxy

    @property
    def galaxies(self) -> list[MISPGalaxy]:
        """Returns a list of galaxies associated to this Attribute"""
        return self.Galaxy

    def _prepare_data(self, data: Path | str | bytes | BytesIO | None) -> None:
        if not data:
            super().__setattr__('data', None)
            return

        if isinstance(data, BytesIO):
            super().__setattr__('data', data)
        elif isinstance(data, Path):
            with data.open('rb') as f_temp:
                super().__setattr__('data', BytesIO(f_temp.read()))
        elif isinstance(data, (str, bytes)):
            super().__setattr__('data', BytesIO(base64.b64decode(data)))
        else:
            raise PyMISPError(f'Invalid type ({type(data)}) for the data key: {data}')

        if self.type == 'malware-sample':
            try:
                # Ignore type, if data is None -> exception
                with ZipFile(self.data) as f:  # type: ignore
                    if not self.__is_misp_encrypted_file(f):
                        raise PyMISPError('Not an existing malware sample')
                    for name in f.namelist():
                        if name.endswith('.filename.txt'):
                            with f.open(name, pwd=b'infected') as unpacked:
                                self.malware_filename = unpacked.read().decode().strip()
                        else:
                            # decrypting a zipped file is extremely slow. We do it on-demand in self.malware_binary
                            continue
            except Exception:
                # not a encrypted zip file, assuming it is a new malware sample
                self._prepare_new_malware_sample()

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ['first_seen', 'last_seen']:
            _datetime = _make_datetime(value)

            # NOTE: the two following should be exceptions, but there are existing events in this state,
            # And we cannot dump them if it is there.
            if name == 'last_seen' and hasattr(self, 'first_seen') and self.first_seen > _datetime:
                logger.warning(f'last_seen ({value}) has to be after first_seen ({self.first_seen})')
            if name == 'first_seen' and hasattr(self, 'last_seen') and self.last_seen < _datetime:
                logger.warning(f'first_seen ({value}) has to be before last_seen ({self.last_seen})')
            super().__setattr__(name, _datetime)
        elif name == 'data':
            self._prepare_data(value)
        else:
            super().__setattr__(name, value)

    def hash_values(self, algorithm: str = 'sha512') -> list[str]:
        """Compute the hash of every value for fast lookups"""
        if algorithm not in hashlib.algorithms_available:
            raise PyMISPError(f'The algorithm {algorithm} is not available for hashing.')
        if '|' in self.type or self.type == 'malware-sample':
            hashes = []
            for v in self.value.split('|'):
                h = hashlib.new(algorithm)
                h.update(v.encode("utf-8"))
                hashes.append(h.hexdigest())
            return hashes
        else:
            h = hashlib.new(algorithm)
            to_encode = self.value
            if not isinstance(to_encode, str):
                to_encode = str(to_encode)
            h.update(to_encode.encode("utf-8"))
            return [h.hexdigest()]

    def _set_default(self) -> None:
        if not hasattr(self, 'comment'):
            self.comment = ''
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.timestamp(datetime.now())

    def _to_feed(self, with_distribution: bool=False) -> dict[str, Any]:
        if with_distribution:
            self._fields_for_feed.add('distribution')
        to_return = super()._to_feed()
        if self.data:
            to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
        if self.tags:
            to_return['Tag'] = list(filter(None, [tag._to_feed() for tag in self.tags]))
        if with_distribution:
            try:
                to_return['SharingGroup'] = self.SharingGroup._to_feed()
            except AttributeError:
                pass
        return to_return

    @property
    def known_types(self) -> list[str]:
        """Returns a list of all the known MISP attributes types"""
        return self.describe_types['types']

    @property
    def malware_binary(self) -> BytesIO | None:
        """Returns a BytesIO of the malware, if the attribute has one.
        Decrypts, unpacks and caches the binary on the first invocation,
        which may require some time for large attachments (~1s/MB).
        """
        if self.type != 'malware-sample':
            # Not a malware sample
            return None
        if hasattr(self, '_malware_binary'):
            # Already unpacked
            return self._malware_binary
        elif hasattr(self, 'malware_filename'):
            # Have a binary, but didn't decrypt it yet
            with ZipFile(self.data) as f:  # type: ignore
                for name in f.namelist():
                    if not name.endswith('.filename.txt'):
                        with f.open(name, pwd=b'infected') as unpacked:
                            self._malware_binary = BytesIO(unpacked.read())
            return self._malware_binary
        return None

    @property
    def shadow_attributes(self) -> list[MISPShadowAttribute]:
        return self.ShadowAttribute

    @shadow_attributes.setter
    def shadow_attributes(self, shadow_attributes: list[MISPShadowAttribute]) -> None:
        """Set a list of prepared MISPShadowAttribute."""
        if all(isinstance(x, MISPShadowAttribute) for x in shadow_attributes):
            self.ShadowAttribute = shadow_attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPShadowAttribute.')

    @property
    def sightings(self) -> list[MISPSighting]:
        return self.Sighting

    @sightings.setter
    def sightings(self, sightings: list[MISPSighting]) -> None:
        """Set a list of prepared MISPSighting."""
        if all(isinstance(x, MISPSighting) for x in sightings):
            self.Sighting = sightings
        else:
            raise PyMISPError('All the attributes have to be of type MISPSighting.')

    def delete(self) -> None:
        """Mark the attribute as deleted (soft delete)"""
        self.deleted = True

    def add_proposal(self, shadow_attribute=None, **kwargs) -> MISPShadowAttribute:  # type: ignore[no-untyped-def]
        """Alias for add_shadow_attribute"""
        return self.add_shadow_attribute(shadow_attribute, **kwargs)

    def add_shadow_attribute(self, shadow_attribute: MISPShadowAttribute | dict[str, Any] | None = None, **kwargs) -> MISPShadowAttribute:  # type: ignore[no-untyped-def]
        """Add a shadow attribute to the attribute (by name or a MISPShadowAttribute object)"""
        if isinstance(shadow_attribute, MISPShadowAttribute):
            misp_shadow_attribute = shadow_attribute
        elif isinstance(shadow_attribute, dict):
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**shadow_attribute)
        elif kwargs:
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**kwargs)
        else:
            raise PyMISPError(f"The shadow_attribute is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict[str, Any]): {shadow_attribute}")
        self.shadow_attributes.append(misp_shadow_attribute)
        self.edited = True
        return misp_shadow_attribute

    def add_sighting(self, sighting: MISPSighting | dict[str, Any] | None = None, **kwargs) -> MISPSighting:  # type: ignore[no-untyped-def]
        """Add a sighting to the attribute (by name or a MISPSighting object)"""
        if isinstance(sighting, MISPSighting):
            misp_sighting = sighting
        elif isinstance(sighting, dict):
            misp_sighting = MISPSighting()
            misp_sighting.from_dict(**sighting)
        elif kwargs:
            misp_sighting = MISPSighting()
            misp_sighting.from_dict(**kwargs)
        else:
            raise PyMISPError(f"The sighting is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict[str, Any]): {sighting}")
        self.sightings.append(misp_sighting)
        self.edited = True
        return misp_sighting

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Attribute' in kwargs:
            kwargs = kwargs['Attribute']
        if kwargs.get('type') and kwargs.get('category'):
            if kwargs['type'] not in self.__category_type_mapping[kwargs['category']]:
                if self.__strict:
                    raise NewAttributeError('{} and {} is an invalid combination, type for this category has to be in {}'.format(
                        kwargs.get('type'), kwargs.get('category'), (', '.join(self.__category_type_mapping[kwargs['category']]))))
                else:
                    kwargs.pop('category', None)

        self.type = kwargs.pop('type', None)  # Required
        if self.type is None:
            raise NewAttributeError('The type of the attribute is required.')
        if self.type not in self.known_types:
            raise NewAttributeError('{} is invalid, type has to be in {}'.format(self.type, (', '.join(self.known_types))))

        type_defaults = self.__sane_default[self.type]

        self.value = kwargs.pop('value', None)
        if self.value is None:
            raise NewAttributeError('The value of the attribute is required.')
        if self.type == 'datetime' and isinstance(self.value, str):
            try:
                # Faster
                if sys.version_info >= (3, 7):
                    self.value = datetime.fromisoformat(self.value)
                else:
                    if '+' in self.value or '-' in self.value:
                        self.value = datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S.%f%z")
                    elif '.' in self.value:
                        self.value = datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S.%f")
                    else:
                        self.value = datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                # Slower, but if the other ones fail, that's a good fallback
                self.value = parse(self.value)

        # Default values
        self.category = kwargs.pop('category', type_defaults['default_category'])
        if self.category is None:
            # In case the category key is passed, but None
            self.category = type_defaults['default_category']
        if self.category not in self.__categories:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(self.category, (', '.join(self.__categories))))

        self.to_ids = kwargs.pop('to_ids', bool(int(type_defaults['to_ids'])))
        if self.to_ids is None:
            self.to_ids = bool(int(type_defaults['to_ids']))
        else:
            self.to_ids = make_bool(self.to_ids)

        if not isinstance(self.to_ids, bool):
            raise NewAttributeError(f'{self.to_ids} is invalid, to_ids has to be True or False')

        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAttributeError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5')

        # other possible values
        if kwargs.get('data'):
            self.data = kwargs.pop('data')
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('event_id'):
            self.event_id = int(kwargs.pop('event_id'))
        if kwargs.get('timestamp'):
            ts = kwargs.pop('timestamp')
            if isinstance(ts, datetime):
                self.timestamp = ts
            else:
                self.timestamp = datetime.fromtimestamp(int(ts), timezone.utc)
        if kwargs.get('first_seen'):
            fs = kwargs.pop('first_seen')
            try:
                # Faster
                self.first_seen = datetime.fromisoformat(fs)
            except Exception:
                # Use __setattr__
                self.first_seen = fs

        if kwargs.get('last_seen'):
            ls = kwargs.pop('last_seen')
            try:
                # Faster
                self.last_seen = datetime.fromisoformat(ls)
            except Exception:
                # Use __setattr__
                self.last_seen = ls

        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewAttributeError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewAttributeError(f'If the distribution is set to sharing group, a sharing group ID is required (cannot be {self.sharing_group_id}).')

        if kwargs.get('Tag'):
            [self.add_tag(tag) for tag in kwargs.pop('Tag')]
        if kwargs.get('Galaxy'):
            [self.add_galaxy(galaxy) for galaxy in kwargs.pop('Galaxy')]
        if kwargs.get('Sighting'):
            [self.add_sighting(sighting) for sighting in kwargs.pop('Sighting')]
        if kwargs.get('ShadowAttribute'):
            [self.add_shadow_attribute(s_attr) for s_attr in kwargs.pop('ShadowAttribute')]

        if kwargs.get('SharingGroup'):
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))
        # If the user wants to disable correlation, let them. Defaults to False.
        self.disable_correlation = kwargs.pop("disable_correlation", False)
        if self.disable_correlation is None:
            self.disable_correlation = False

        super().from_dict(**kwargs)

    def to_dict(self, json_format: bool = False) -> dict[str, Any]:
        to_return = super().to_dict(json_format)
        if self.data:
            to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
        return to_return

    def _prepare_new_malware_sample(self) -> None:
        if '|' in self.value:
            # Get the filename, ignore the md5, because humans.
            self.malware_filename, md5 = self.value.rsplit('|', 1)
        else:
            # Assuming the user only passed the filename
            self.malware_filename = self.value
        self.value = self.malware_filename
        self._malware_binary = self.data
        self.encrypt = True

    def __is_misp_encrypted_file(self, f: ZipFile) -> bool:
        files_list = f.namelist()
        if len(files_list) != 2:
            return False
        md5_from_filename = ''
        md5_from_file = ''
        for name in files_list:
            if name.endswith('.filename.txt'):
                md5_from_filename = name.replace('.filename.txt', '')
            else:
                md5_from_file = name
        if not md5_from_filename or not md5_from_file or md5_from_filename != md5_from_file:
            return False
        return True

    def __repr__(self) -> str:
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(type={self.type}, value={self.value})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPObjectReference(AbstractMISP):

    _fields_for_feed: set[str] = {'uuid', 'timestamp', 'relationship_type', 'comment',
                                  'object_uuid', 'referenced_uuid'}

    def __init__(self) -> None:
        super().__init__()
        self.uuid = str(uuid.uuid4())
        self.object_uuid: str
        self.referenced_uuid: str
        self.relationship_type: str

    def _set_default(self) -> None:
        if not hasattr(self, 'comment'):
            self.comment = ''
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.timestamp(datetime.now())

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'ObjectReference' in kwargs:
            kwargs = kwargs['ObjectReference']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'referenced_uuid') and hasattr(self, 'object_uuid'):
            return '<{self.__class__.__name__}(object_uuid={self.object_uuid}, referenced_uuid={self.referenced_uuid}, relationship_type={self.relationship_type})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPObject(AnalystDataBehaviorMixin):

    _fields_for_feed: set[str] = {'name', 'meta-category', 'description', 'template_uuid',
                                  'template_version', 'uuid', 'timestamp', 'comment',
                                  'first_seen', 'last_seen', 'deleted'}

    _analyst_data_object_type = 'Object'

    def __init__(self, name: str, strict: bool = False, standalone: bool = True,  # type: ignore[no-untyped-def]
                 default_attributes_parameters: dict[str, Any] = {}, **kwargs) -> None:
        ''' Master class representing a generic MISP object

        :param name: Name of the object
        :param strict: Enforce validation with the object templates
        :param standalone: The object will be pushed as directly on MISP, not as a part of an event.
            In this case the ObjectReference needs to be pushed manually and cannot be in the JSON dump.
        :param default_attributes_parameters: Used as template for the attributes if they are not overwritten in add_attribute
        :param misp_objects_path_custom: Path to custom object templates
        :param misp_objects_template_custom: Template of the object. Expects the content (dict, loaded with json.load or json.loads) of a template definition file, see repository MISP/misp-objects.
        '''
        super().__init__(**kwargs)
        self._strict: bool = strict
        self.name: str = name
        self._known_template: bool = False
        self.id: int
        self._definition: dict[str, Any] | None
        self.timestamp: float | int | datetime

        misp_objects_template_custom = kwargs.pop('misp_objects_template_custom', None)
        misp_objects_path_custom = kwargs.pop('misp_objects_path_custom', None)
        if misp_objects_template_custom:
            self._set_template(misp_objects_template_custom=misp_objects_template_custom)
        else:
            # Fall back to default path if None
            self._set_template(misp_objects_path_custom=misp_objects_path_custom)

        self.uuid: str = str(uuid.uuid4())
        self.first_seen: datetime
        self.last_seen: datetime
        self.__fast_attribute_access: dict[str, Any] = defaultdict(list)  # Hashtable object_relation: [attributes]
        self.ObjectReference: list[MISPObjectReference] = []
        self._standalone: bool = False
        self.Attribute: list[MISPObjectAttribute] = []
        self.SharingGroup: MISPSharingGroup
        self._default_attributes_parameters: dict[str, Any]
        if isinstance(default_attributes_parameters, MISPAttribute):
            # Just make sure we're not modifying an existing MISPAttribute
            self._default_attributes_parameters = default_attributes_parameters.to_dict()
        else:
            self._default_attributes_parameters = copy.copy(default_attributes_parameters)
        if self._default_attributes_parameters:
            # Let's clean that up
            self._default_attributes_parameters.pop('value', None)  # duh
            self._default_attributes_parameters.pop('uuid', None)  # duh
            self._default_attributes_parameters.pop('id', None)  # duh
            self._default_attributes_parameters.pop('object_id', None)  # duh
            self._default_attributes_parameters.pop('type', None)  # depends on the value
            self._default_attributes_parameters.pop('object_relation', None)  # depends on the value
            self._default_attributes_parameters.pop('disable_correlation', None)  # depends on the value
            self._default_attributes_parameters.pop('to_ids', None)  # depends on the value
            self._default_attributes_parameters.pop('deleted', None)  # doesn't make sense to pre-set it
            self._default_attributes_parameters.pop('data', None)  # in case the original in a sample or an attachment

            # Those values are set for the current object, if they exist, but not pop'd because they are still useful for the attributes
            self.distribution: int = self._default_attributes_parameters.get('distribution', 5)
            self.sharing_group_id: int = self._default_attributes_parameters.get('sharing_group_id', 0)
        else:
            self.distribution = 5  # Default to inherit
            self.sharing_group_id = 0
        self.standalone = standalone

    def _load_template_path(self, template_path: Path | str) -> bool:
        template = self._load_json(template_path)
        if not template:
            self._definition = None
            return False
        self._load_template(template)
        return True

    def _load_template(self, template: dict[str, Any]) -> None:
        self._definition = template
        setattr(self, 'meta-category', self._definition['meta-category'])
        self.template_uuid = self._definition['uuid']
        self.description = self._definition['description']
        self.template_version = self._definition['version']

    def _set_default(self) -> None:
        if not hasattr(self, 'comment'):
            self.comment = ''
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.timestamp(datetime.now())

    def _to_feed(self, with_distribution: bool=False) -> dict[str, Any]:
        if with_distribution:
            self._fields_for_feed.add('distribution')
        if not hasattr(self, 'template_uuid'):  # workaround for old events where the template_uuid was not yet mandatory
            self.template_uuid = str(uuid.uuid5(uuid.UUID("9319371e-2504-4128-8410-3741cebbcfd3"), self.name))
        if not hasattr(self, 'description'):    # workaround for old events where description is not always set
            self.description = '<unknown>'
        if not hasattr(self, 'meta-category'):  # workaround for old events where meta-category is not always set
            setattr(self, 'meta-category', 'misc')
        to_return = super()._to_feed()
        if self.references:
            to_return['ObjectReference'] = [reference._to_feed() for reference in self.references]
        if with_distribution:
            try:
                to_return['SharingGroup'] = self.SharingGroup._to_feed()
            except AttributeError:
                pass
        return to_return

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ['first_seen', 'last_seen']:
            value = _make_datetime(value)

            if name == 'last_seen' and hasattr(self, 'first_seen') and self.first_seen > value:
                logger.warning(f'last_seen ({value}) has to be after first_seen ({self.first_seen})')
            if name == 'first_seen' and hasattr(self, 'last_seen') and self.last_seen < value:
                logger.warning(f'first_seen ({value}) has to be before last_seen ({self.last_seen})')
        super().__setattr__(name, value)

    def force_misp_objects_path_custom(self, misp_objects_path_custom: Path | str, object_name: str | None = None) -> None:
        if object_name:
            self.name = object_name
        self._set_template(misp_objects_path_custom)

    def _set_template(self, misp_objects_path_custom: Path | str | None = None, misp_objects_template_custom: dict[str, Any] | None = None) -> None:
        if misp_objects_template_custom:
            # A complete template was given to the constructor
            self._load_template(misp_objects_template_custom)
            self._known_template = True
        else:
            if misp_objects_path_custom:
                # If misp_objects_path_custom is given, and an object with the given name exists, use that.
                if isinstance(misp_objects_path_custom, str):
                    self.misp_objects_path = Path(misp_objects_path_custom)
                else:
                    self.misp_objects_path = misp_objects_path_custom

            # Try to get the template
            self._known_template = self._load_template_path(self.misp_objects_path / self.name / 'definition.json')

        if not self._known_template and self._strict:
            raise UnknownMISPObjectTemplate(f'{self.name} is unknown in the MISP object directory.')
        else:
            # Then we have no meta-category, template_uuid, description and template_version
            pass

    def delete(self) -> None:
        """Mark the object as deleted (soft delete)"""
        self.deleted = True
        for a in self.attributes:
            a.delete()

    @property
    def disable_validation(self) -> None:
        self._strict = False

    @property
    def attributes(self) -> list[MISPObjectAttribute]:
        return self.Attribute

    @attributes.setter
    def attributes(self, attributes: list[MISPObjectAttribute]) -> None:
        if all(isinstance(x, MISPObjectAttribute) for x in attributes):
            self.Attribute = attributes
            self.__fast_attribute_access = defaultdict(list)
        else:
            raise PyMISPError('All the attributes have to be of type MISPObjectAttribute.')

    @property
    def references(self) -> list[MISPObjectReference]:
        return self.ObjectReference

    @references.setter
    def references(self, references: list[MISPObjectReference]) -> None:
        if all(isinstance(x, MISPObjectReference) for x in references):
            self.ObjectReference = references
        else:
            raise PyMISPError('All the attributes have to be of type MISPObjectReference.')

    @property
    def standalone(self) -> bool:
        return self._standalone

    @standalone.setter
    def standalone(self, new_standalone: bool) -> None:
        if self._standalone != new_standalone:
            if new_standalone:
                self.update_not_jsonable("ObjectReference")
            else:
                self._remove_from_not_jsonable("ObjectReference")
            self._standalone = new_standalone
        else:
            pass

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Object' in kwargs:
            kwargs = kwargs['Object']
        if self._known_template:
            if kwargs.get('template_uuid') and kwargs['template_uuid'] != self.template_uuid:
                if self._strict:
                    raise UnknownMISPObjectTemplate('UUID of the object is different from the one of the template.')
                else:
                    self._known_template = False
            if kwargs.get('template_version') and int(kwargs['template_version']) != self.template_version:
                if self._strict:
                    raise UnknownMISPObjectTemplate('Version of the object ({}) is different from the one of the template ({}).'.format(kwargs['template_version'], self.template_version))
                else:
                    self._known_template = False

        # depending on how the object is initialized, we may have a few keys to pop
        kwargs.pop('misp_objects_template_custom', None)
        kwargs.pop('misp_objects_path_custom', None)

        if 'distribution' in kwargs and kwargs['distribution'] is not None:
            self.distribution = kwargs.pop('distribution')
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAttributeError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5')

        if kwargs.get('timestamp'):
            ts = kwargs.pop('timestamp')
            if isinstance(ts, datetime):
                self.timestamp = ts
            else:
                self.timestamp = datetime.fromtimestamp(int(ts), timezone.utc)

        if kwargs.get('first_seen'):
            fs = kwargs.pop('first_seen')
            try:
                # Faster
                self.first_seen = datetime.fromisoformat(fs)
            except Exception:
                # Use __setattr__
                self.first_seen = fs

        if kwargs.get('last_seen'):
            ls = kwargs.pop('last_seen')
            try:
                # Faster
                self.last_seen = datetime.fromisoformat(ls)
            except Exception:
                # Use __setattr__
                self.last_seen = ls

        if kwargs.get('Attribute'):
            [self.add_attribute(**a) for a in kwargs.pop('Attribute')]
        if kwargs.get('ObjectReference'):
            [self.add_reference(**r) for r in kwargs.pop('ObjectReference')]

        if kwargs.get('SharingGroup'):
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))
        # Not supported yet - https://github.com/MISP/PyMISP/issues/168
        # if kwargs.get('Tag'):
        #    for tag in kwargs.pop('Tag'):
        #        self.add_tag(tag)

        super().from_dict(**kwargs)

    def add_reference(self, referenced_uuid: AbstractMISP | str, relationship_type: str, comment: str | None = None, **kwargs) -> MISPObjectReference:  # type: ignore[no-untyped-def]
        """Add a link (uuid) to another object"""
        if isinstance(referenced_uuid, AbstractMISP):
            # Allow to pass an object or an attribute instead of its UUID
            referenced_uuid = referenced_uuid.uuid
        if 'object_uuid' in kwargs and not kwargs.get('object_uuid'):
            # Unexplained None in object_uuid key -> https://github.com/MISP/PyMISP/issues/640
            kwargs.pop('object_uuid')
            object_uuid = self.uuid
        elif kwargs.get('object_uuid'):
            # Load existing object
            object_uuid = kwargs.pop('object_uuid')
        else:
            # New reference
            object_uuid = self.uuid
        reference = MISPObjectReference()
        reference.from_dict(object_uuid=object_uuid, referenced_uuid=referenced_uuid,
                            relationship_type=relationship_type, comment=comment, **kwargs)
        self.ObjectReference.append(reference)
        self.edited = True
        return reference

    def get_attribute_by_id(self, attribute_id: str | int) -> MISPObjectAttribute:
        """Get an object attribute by ID

        :param attribute_id: The ID of the seeking object attribute"""
        for attribute in self.attributes:
            if hasattr(attribute, 'id') and attribute.id == attribute_id:
                return attribute

        raise InvalidMISPObjectAttribute(f'Object attribute with {attribute_id} does not exist in this event')

    def get_attribute_by_uuid(self, attribute_uuid: str) -> MISPObjectAttribute:
        """Get an object attribute by UUID

        :param attribute_uuid: The UUID of the seeking object attribute"""
        for attribute in self.attributes:
            if hasattr(attribute, 'uuid') and attribute.uuid == attribute_uuid:
                return attribute

        raise InvalidMISPObjectAttribute(f'Object attribute with {attribute_uuid} does not exist in this event')

    def get_attributes_by_relation(self, object_relation: str) -> list[MISPAttribute]:
        '''Returns the list of attributes with the given object relation in the object'''
        return self._fast_attribute_access.get(object_relation, [])

    @property
    def _fast_attribute_access(self) -> dict[str, Any]:
        if not self.__fast_attribute_access:
            for a in self.attributes:
                self.__fast_attribute_access[a.object_relation].append(a)
        return self.__fast_attribute_access

    def has_attributes_by_relation(self, list_of_relations: list[str]) -> bool:
        '''True if all the relations in the list are defined in the object'''
        return all(relation in self._fast_attribute_access for relation in list_of_relations)

    def add_attribute(self, object_relation: str, simple_value: str | int | float | None = None, **value) -> MISPAttribute | None:  # type: ignore[no-untyped-def]
        """Add an attribute.
        :param object_relation: The object relation of the attribute you're adding to the object
        :param simple_value: The value
        :param value: dictionary with all the keys supported by MISPAttribute

        Note: as long as PyMISP knows about the object template, only the object_relation and the simple_value are required.
              If PyMISP doesn't know the template, you also **must** pass a type.
              All the other options that can be passed along when creating an attribute (comment, IDS flag, ...)
              will be either taked out of the template, or out of the default setting for the type as defined on the MISP instance.
        """
        if simple_value is not None:  # /!\ The value *can* be 0
            value['value'] = simple_value
        if value.get('value') is None:
            logger.warning(f"The value of the attribute you're trying to add is None, skipping it. Object relation: {object_relation}")
            return None
        else:
            if isinstance(value['value'], bytes):
                # That shouldn't happen, but we live in the real world, and it does.
                # So we try to decode (otherwise, MISP barf), and raise a warning if needed.
                try:
                    value['value'] = value['value'].decode()
                except Exception:
                    logger.warning("The value of the attribute you're trying to add is a bytestream ({!r}), and we're unable to make it a string.".format(value['value']))
                    return None

            # Make sure we're not adding an empty value.
            if isinstance(value['value'], str):
                value['value'] = value['value'].strip().strip('\x00')
                if value['value'] == '':
                    logger.warning(f"The value of the attribute you're trying to add is an empty string, skipping it. Object relation: {object_relation}")
                    return None
        if self._known_template and self._definition:
            if object_relation in self._definition['attributes']:
                attribute = MISPObjectAttribute(self._definition['attributes'][object_relation])
            else:
                # Woopsie, this object_relation is unknown, no sane defaults for you.
                logger.warning(f"The template ({self.name}) doesn't have the object_relation ({object_relation}) you're trying to add. If you are creating a new event to push to MISP, please review your code so it matches the template.")
                attribute = MISPObjectAttribute({})
        else:
            attribute = MISPObjectAttribute({})
        # Overwrite the parameters of self._default_attributes_parameters with the ones of value
        attribute.from_dict(object_relation=object_relation, **{**self._default_attributes_parameters, **value})
        self.__fast_attribute_access[object_relation].append(attribute)
        self.Attribute.append(attribute)
        self.edited = True
        return attribute

    def add_attributes(self, object_relation: str, *attributes: Sequence[str | dict[str, Any] | MISPAttribute]) -> list[MISPAttribute | None]:
        '''Add multiple attributes with the same object_relation.
        Helper for object_relation when multiple is True in the template.
        It is the same as calling multiple times add_attribute with the same object_relation.
        '''
        to_return = []
        for attribute in attributes:
            if isinstance(attribute, MISPAttribute):
                a = self.add_attribute(object_relation, **attribute.to_dict())
            elif isinstance(attribute, dict):
                a = self.add_attribute(object_relation, **attribute)  # type: ignore[misc]
            else:
                a = self.add_attribute(object_relation, value=attribute)
            to_return.append(a)
        return to_return

    def to_dict(self, json_format: bool = False, strict: bool = False) -> dict[str, Any]:
        if strict or self._strict and self._known_template:
            self._validate()
        return super().to_dict(json_format)

    def to_json(self, sort_keys: bool = False, indent: int | None = None, strict: bool = False) -> str:
        if strict or self._strict and self._known_template:
            self._validate()
        return super().to_json(sort_keys=sort_keys, indent=indent)

    def _validate(self) -> bool:
        if not self._definition:
            raise PyMISPError('No object definition available, unable to validate.')
        """Make sure the object we're creating has the required fields"""
        if self._definition.get('required'):
            required_missing = set(self._definition['required']) - set(self._fast_attribute_access.keys())
            if required_missing:
                raise InvalidMISPObject(f'{required_missing} are required.')
        if self._definition.get('requiredOneOf'):
            if not set(self._definition['requiredOneOf']) & set(self._fast_attribute_access.keys()):
                # We ecpect at least one of the object_relation in requiredOneOf, and it isn't the case
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self._definition['requiredOneOf'])))
        for rel, attrs in self._fast_attribute_access.items():
            if len(attrs) == 1:
                # object_relation's here only once, everything's cool, moving on
                continue
            if not self._definition['attributes'][rel].get('multiple'):
                # object_relation's here more than once, but it isn't allowed in the template.
                raise InvalidMISPObject(f'Multiple occurrences of {rel} is not allowed')
        return True

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPEventReport(AnalystDataBehaviorMixin):

    _fields_for_feed: set[str] = {'uuid', 'name', 'content', 'timestamp', 'deleted'}
    _analyst_data_object_type = 'EventReport'

    timestamp: float | int | datetime

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.uuid: str = str(uuid.uuid4())

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'EventReport' in kwargs:
            kwargs = kwargs['EventReport']

        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewEventReportError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5')

        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewEventReportError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewEventReportError(f'If the distribution is set to sharing group, a sharing group ID is required (cannot be {self.sharing_group_id}).')

        self.name = kwargs.pop('name', None)
        if self.name is None:
            raise NewEventReportError('The name of the event report is required.')

        self.content = kwargs.pop('content', None)
        if self.content is None:
            raise NewAttributeError('The content of the event report is required.')

        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('event_id'):
            self.event_id = int(kwargs.pop('event_id'))
        if kwargs.get('timestamp'):
            ts = kwargs.pop('timestamp')
            if isinstance(ts, datetime):
                self.timestamp = ts
            else:
                self.timestamp = datetime.fromtimestamp(int(ts), timezone.utc)
        if kwargs.get('deleted'):
            self.deleted = kwargs.pop('deleted')

        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'

    def _set_default(self) -> None:
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.timestamp(datetime.now())
        if not hasattr(self, 'name'):
            self.name = ''
        if not hasattr(self, 'content'):
            self.content = ''


class MISPGalaxyClusterElement(AbstractMISP):
    """A MISP Galaxy cluster element, providing further info on a cluster

    Creating a new galaxy cluster element can take the following parameters

    :param key: The key/identifier of the element
    :type key: str
    :param value: The value of the element
    :type value: str
    """

    key: str
    value: str

    def __repr__(self) -> str:
        if hasattr(self, 'key') and hasattr(self, 'value'):
            return '<{self.__class__.__name__}(key={self.key}, value={self.value})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'

    def __setattr__(self, key: str, value: Any) -> None:
        if key == "value" and isinstance(value, list):
            raise PyMISPError("You tried to set a list to a cluster element's value. "
                              "Instead, create seperate elements for each value")
        super().__setattr__(key, value)

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('galaxy_cluster_id'):
            self.galaxy_cluster_id = int(kwargs.pop('galaxy_cluster_id'))

        super().from_dict(**kwargs)


class MISPGalaxyClusterRelation(AbstractMISP):
    """A MISP Galaxy cluster relation, linking one cluster to another

    Creating a new galaxy cluster can take the following parameters

    :param galaxy_cluster_uuid: The UUID of the galaxy the relation links to
    :param referenced_galaxy_cluster_type: The relation type, e.g. dropped-by
    :param referenced_galaxy_cluster_uuid: The UUID of the related galaxy
    :param distribution: The distribution of the relation, one of 0, 1, 2, 3, 4, default 0
    :param sharing_group_id: The sharing group of the relation, only when distribution is 4
    """

    def __repr__(self) -> str:
        if hasattr(self, "referenced_galaxy_cluster_type"):
            return '<{self.__class__.__name__}(referenced_galaxy_cluster_type={self.referenced_galaxy_cluster_type})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'

    def __init__(self) -> None:
        super().__init__()
        self.galaxy_cluster_uuid: str
        self.referenced_galaxy_cluster_uuid: str
        self.distribution: int = 0
        self.referenced_galaxy_cluster_type: str
        self.Tag: list[MISPTag] = []

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        # Default values for a valid event to send to a MISP instance
        self.distribution = int(kwargs.pop('distribution', 0))
        if self.distribution not in [0, 1, 2, 3, 4, 5]:
            raise NewGalaxyClusterRelationError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4')

        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewGalaxyClusterRelationError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewGalaxyClusterRelationError(f'If the distribution is set to sharing group, a sharing group ID is required (cannot be {self.sharing_group_id}).')

        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('orgc_id'):
            self.orgc_id = int(kwargs.pop('orgc_id'))
        if kwargs.get('org_id'):
            self.org_id = int(kwargs.pop('org_id'))
        if kwargs.get('galaxy_id'):
            self.galaxy_id = int(kwargs.pop('galaxy_id'))
        if kwargs.get('tag_id'):
            self.tag_id = int(kwargs.pop('tag_id'))
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))
        if kwargs.get('Tag'):
            [self.add_tag(**t) for t in kwargs.pop('Tag')]
        if kwargs.get('SharingGroup'):
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))
        super().from_dict(**kwargs)

    def add_tag(self, tag: str | MISPTag | dict[str, Any] | None = None, **kwargs) -> MISPTag:  # type: ignore[no-untyped-def]
        return super()._add_tag(tag, **kwargs)

    @property
    def tags(self) -> list[MISPTag]:
        """Returns a list of tags associated to this Attribute"""
        return self.Tag

    @tags.setter
    def tags(self, tags: list[MISPTag]) -> None:
        """Set a list of prepared MISPTag."""
        super()._set_tags(tags)


class MISPGalaxyCluster(AbstractMISP):
    """A MISP galaxy cluster, storing respective galaxy elements and relations.
    Used to view default galaxy clusters and add/edit/update/delete Galaxy 2.0 clusters

    Creating a new galaxy cluster can take the following parameters

    :param value: The value of the galaxy cluster
    :type value: str
    :param description: The description of the galaxy cluster
    :type description: str
    :param distribution: The distribution type, one of 0, 1, 2, 3, 4
    :type distribution: int
    :param sharing_group_id: The sharing group ID, if distribution is set to 4
    :type sharing_group_id: int, optional
    :param authors: A list of authors of the galaxy cluster
    :type authors: list[str], optional
    :param cluster_elements: List of MISPGalaxyClusterElement
    :type cluster_elements: list[MISPGalaxyClusterElement], optional
    :param cluster_relations: List of MISPGalaxyClusterRelation
    :type cluster_relations: list[MISPGalaxyClusterRelation], optional
    """

    id: int | str | None
    tag_name: str
    galaxy_id: str | None

    def __init__(self) -> None:
        super().__init__()
        self.Galaxy: MISPGalaxy
        self.GalaxyElement: list[MISPGalaxyClusterElement] = []
        self.meta: dict[str, Any] = {}
        self.GalaxyClusterRelation: list[MISPGalaxyClusterRelation] = []
        self.Org: MISPOrganisation
        self.Orgc: MISPOrganisation
        self.SharingGroup: MISPSharingGroup
        self.value: str
        # Set any inititialized cluster to be False
        self.default = False

    @property
    def cluster_elements(self) -> list[MISPGalaxyClusterElement]:
        return self.GalaxyElement

    @cluster_elements.setter
    def cluster_elements(self, cluster_elements: list[MISPGalaxyClusterElement]) -> None:
        self.GalaxyElement = cluster_elements

    @property
    def cluster_relations(self) -> list[MISPGalaxyClusterRelation]:
        return self.GalaxyClusterRelation

    @cluster_relations.setter
    def cluster_relations(self, cluster_relations: list[MISPGalaxyClusterRelation]) -> None:
        self.GalaxyClusterRelation = cluster_relations

    def parse_meta_as_elements(self) -> None:
        """Function to parse the meta field into GalaxyClusterElements"""
        # Parse the cluster elements from the kwargs meta fields
        for key, value in self.meta.items():
            # The meta will merge fields together, i.e. Two 'countries' will be a list, so split these up
            if not isinstance(value, list):
                value = [value]
            for v in value:
                self.add_cluster_element(key=key, value=v)

    @property
    def elements_meta(self) -> dict[str, Any]:
        """Function to return the galaxy cluster elements as a dictionary structure of lists
        that comes from a MISPGalaxy within a MISPEvent. Lossy, you lose the element ID
        """
        response = defaultdict(list)
        for element in self.cluster_elements:
            response[element.key].append(element.value)
        return dict(response)

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'GalaxyCluster' in kwargs:
            kwargs = kwargs['GalaxyCluster']
        self.default = kwargs.pop('default', False)
        # If the default field is set, we shouldn't have distribution or sharing group ID set
        if self.default:
            blocked_fields = ["distribution" "sharing_group_id"]
            for field in blocked_fields:
                if kwargs.get(field, None):
                    raise NewGalaxyClusterError(
                        f"The field '{field}' cannot be set on a default galaxy cluster"
                    )

        self.distribution = int(kwargs.pop('distribution', 0))
        if self.distribution not in [0, 1, 2, 3, 4]:
            raise NewGalaxyClusterError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4')

        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewGalaxyClusterError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewGalaxyClusterError(f'If the distribution is set to sharing group, a sharing group ID is required (cannot be {self.sharing_group_id}).')

        if 'uuid' in kwargs:
            self.uuid = kwargs.pop('uuid')
        if 'meta' in kwargs:
            self.meta = kwargs.pop('meta')
        if 'Galaxy' in kwargs:
            self.Galaxy = MISPGalaxy()
            self.Galaxy.from_dict(**kwargs.pop('Galaxy'))
        if 'GalaxyElement' in kwargs:
            [self.add_cluster_element(**e) for e in kwargs.pop('GalaxyElement')]
        if 'Org' in kwargs:
            self.Org = MISPOrganisation()
            self.Org.from_dict(**kwargs.pop('Org'))
        if 'Orgc' in kwargs:
            self.Orgc = MISPOrganisation()
            self.Orgc.from_dict(**kwargs.pop('Orgc'))
        if 'GalaxyClusterRelation' in kwargs:
            [self.add_cluster_relation(**r) for r in kwargs.pop('GalaxyClusterRelation')]
        if 'SharingGroup' in kwargs:
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))
        super().from_dict(**kwargs)

    def add_cluster_element(self, key: str, value: str, **kwargs) -> MISPGalaxyClusterElement:  # type: ignore[no-untyped-def]
        """Add a cluster relation to a MISPGalaxyCluster, key and value are required

        :param key: The key name of the element
        :type key: str
        :param value: The value of the element
        :type value: str
        """

        cluster_element = MISPGalaxyClusterElement()
        cluster_element.from_dict(key=key, value=value, **kwargs)
        self.cluster_elements.append(cluster_element)
        return cluster_element

    def add_cluster_relation(self, referenced_galaxy_cluster_uuid: MISPGalaxyCluster | str | UUID, referenced_galaxy_cluster_type: str, galaxy_cluster_uuid: str | None = None, **kwargs: dict[str, Any]) -> MISPGalaxyClusterRelation:
        """Add a cluster relation to a MISPGalaxyCluster.

        :param referenced_galaxy_cluster_uuid: UUID of the related cluster
        :type referenced_galaxy_cluster_uuid: uuid
        :param referenced_galaxy_cluster_type: Relation type
        :type referenced_galaxy_cluster_type: uuid
        :param galaxy_cluster_uuid: UUID of this cluster, leave blank to use the stored UUID
        :param galaxy_cluster_uuid: uuid, Optional
        """

        if not getattr(self, "uuid", None):
            raise PyMISPError("The cluster does not have a UUID, make sure it is a valid galaxy cluster")
        cluster_relation = MISPGalaxyClusterRelation()

        if isinstance(referenced_galaxy_cluster_uuid, MISPGalaxyCluster):
            referenced_galaxy_cluster_uuid = referenced_galaxy_cluster_uuid.uuid

        cluster_relation.from_dict(
            referenced_galaxy_cluster_uuid=referenced_galaxy_cluster_uuid,
            referenced_galaxy_cluster_type=referenced_galaxy_cluster_type,
            galaxy_cluster_uuid=galaxy_cluster_uuid or self.uuid,
            **kwargs
        )
        self.cluster_relations.append(cluster_relation)
        return cluster_relation

    def __repr__(self) -> str:
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(value={self.value})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPGalaxy(AbstractMISP):
    """Galaxy class, used to view a galaxy and respective clusters"""

    id: str | None

    def __init__(self) -> None:
        super().__init__()
        self.GalaxyCluster: list[MISPGalaxyCluster] = []
        self.name: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """Galaxy could be in one of the following formats:
        {'Galaxy': {}, 'GalaxyCluster': []}
        {'Galaxy': {'GalaxyCluster': []}}
        """

        if 'GalaxyCluster' in kwargs and kwargs.get("withCluster", True):
            # Parse the cluster from the kwargs
            [self.add_galaxy_cluster(**e) for e in kwargs.pop('GalaxyCluster')]

        if 'Galaxy' in kwargs:
            kwargs = kwargs['Galaxy']
        super().from_dict(**kwargs)

    @property
    def clusters(self) -> list[MISPGalaxyCluster]:
        return self.GalaxyCluster

    def add_galaxy_cluster(self, **kwargs) -> MISPGalaxyCluster:  # type: ignore[no-untyped-def]
        """Add a MISP galaxy cluster into a MISPGalaxy.
        Supports all other parameters supported by MISPGalaxyCluster"""

        galaxy_cluster = MISPGalaxyCluster()
        galaxy_cluster.from_dict(**kwargs)
        self.clusters.append(galaxy_cluster)
        return galaxy_cluster

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPEvent(AnalystDataBehaviorMixin):

    _fields_for_feed: set[str] = {'uuid', 'info', 'threat_level_id', 'analysis', 'timestamp',
                                  'publish_timestamp', 'published', 'date', 'extends_uuid'}

    _analyst_data_object_type = 'Event'

    def __init__(self, describe_types: dict[str, Any] | None = None, strict_validation: bool = False, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        self.__schema_file = 'schema.json' if strict_validation else 'schema-lax.json'

        if describe_types:
            # This variable is used in add_attribute in order to avoid duplicating the structure
            self.describe_types = describe_types

        self.uuid: str = str(uuid.uuid4())
        self.date: date
        self.Attribute: list[MISPAttribute] = []
        self.Object: list[MISPObject] = []
        self.RelatedEvent: list[MISPEvent] = []
        self.ShadowAttribute: list[MISPShadowAttribute] = []
        self.SharingGroup: MISPSharingGroup
        self.EventReport: list[MISPEventReport] = []
        self.Tag: list[MISPTag] = []
        self.Galaxy: list[MISPGalaxy] = []

        self.publish_timestamp: float | int | datetime
        self.timestamp: float | int | datetime

    def add_tag(self, tag: str | MISPTag | dict[str, Any] | None = None, **kwargs) -> MISPTag:  # type: ignore[no-untyped-def]
        return super()._add_tag(tag, **kwargs)

    @property
    def tags(self) -> list[MISPTag]:
        """Returns a list of tags associated to this Event"""
        return self.Tag

    @tags.setter
    def tags(self, tags: list[MISPTag]) -> None:
        """Set a list of prepared MISPTag."""
        super()._set_tags(tags)

    def _set_default(self) -> None:
        """There are a few keys that could, or need to be set by default for the feed generator"""
        if not hasattr(self, 'published'):
            self.published = True
        if not hasattr(self, 'uuid'):
            self.uuid = str(uuid.uuid4())
        if not hasattr(self, 'extends_uuid'):
            self.extends_uuid = ''
        if not hasattr(self, 'date'):
            self.set_date(date.today())
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.timestamp(datetime.now())
        if not hasattr(self, 'publish_timestamp'):
            self.publish_timestamp = datetime.timestamp(datetime.now())
        if not hasattr(self, 'analysis'):
            # analysis: 0 means initial, 1 ongoing, 2 completed
            self.analysis = 2
        if not hasattr(self, 'threat_level_id'):
            # threat_level_id 4 means undefined. Tags are recommended.
            self.threat_level_id = 4

    @property
    def manifest(self) -> dict[str, Any]:
        required = ['info', 'Orgc']
        for r in required:
            if not hasattr(self, r):
                raise PyMISPError('The field {} is required to generate the event manifest.')

        self._set_default()

        return {
            self.uuid: {
                'Orgc': self.Orgc._to_feed(),
                'Tag': list(filter(None, [tag._to_feed() for tag in self.tags])),
                'info': self.info,
                'date': self.date.isoformat(),
                'analysis': self.analysis,
                'threat_level_id': self.threat_level_id,
                'timestamp': self._datetime_to_timestamp(self.timestamp)
            }
        }

    def attributes_hashes(self, algorithm: str = 'sha512') -> list[str]:
        to_return: list[str] = []
        for attribute in self.attributes:
            to_return += attribute.hash_values(algorithm)
        for obj in self.objects:
            for attribute in obj.attributes:
                to_return += attribute.hash_values(algorithm)
        return to_return

    def to_feed(self, valid_distributions: list[int] = [0, 1, 2, 3, 4, 5], with_meta: bool = False, with_distribution: bool=False, with_local_tags: bool = True, with_event_reports: bool = True) -> dict[str, Any]:
        """ Generate a json output for MISP Feed.

        :param valid_distributions: only makes sense if the distribution key is set; i.e., the event is exported from a MISP instance.
        :param with_distribution: exports distribution and Sharing Group info; otherwise all SharingGroup information is discarded (protecting privacy)
        :param with_local_tags: tag export includes local exportable tags along with global exportable tags
        :param with_event_reports: include event reports in the returned MISP event
        """
        required = ['info', 'Orgc']
        for r in required:
            if not hasattr(self, r):
                raise PyMISPError(f'The field {r} is required to generate the event feed output.')

        if (hasattr(self, 'distribution')
                and self.distribution is not None
                and int(self.distribution) not in valid_distributions):
            return {}

        if with_distribution:
            self._fields_for_feed.add('distribution')

        to_return = super()._to_feed()
        if with_meta:
            to_return['_hashes'] = []
            to_return['_manifest'] = self.manifest

        to_return['Orgc'] = self.Orgc._to_feed()
        to_return['Tag'] = list(filter(None, [tag._to_feed(with_local_tags) for tag in self.tags]))
        if self.attributes:
            to_return['Attribute'] = []
            for attribute in self.attributes:
                if (valid_distributions and attribute.get('distribution') is not None and attribute.distribution not in valid_distributions):
                    continue
                to_return['Attribute'].append(attribute._to_feed(with_distribution=with_distribution))
                if with_meta:
                    to_return['_hashes'] += attribute.hash_values('md5')

        if self.objects:
            to_return['Object'] = []
            for obj in self.objects:
                if (valid_distributions and obj.get('distribution') is not None and obj.distribution not in valid_distributions):
                    continue
                if with_distribution:
                    obj._fields_for_feed.add('distribution')
                obj_to_attach = obj._to_feed(with_distribution=with_distribution)
                obj_to_attach['Attribute'] = []
                for attribute in obj.attributes:
                    if (valid_distributions and attribute.get('distribution') is not None and attribute.distribution not in valid_distributions):
                        continue
                    obj_to_attach['Attribute'].append(attribute._to_feed(with_distribution=with_distribution))
                    if with_meta:
                        to_return['_hashes'] += attribute.hash_values('md5')
                to_return['Object'].append(obj_to_attach)

        if with_distribution:
            try:
                to_return['SharingGroup'] = self.SharingGroup._to_feed()
            except AttributeError:
                pass

        if with_event_reports and self.event_reports:
            to_return['EventReport'] = []
            for event_report in self.event_reports:
                if (valid_distributions and event_report.get('distribution') is not None and event_report.distribution not in valid_distributions):
                    continue
                if not with_distribution:
                    event_report.pop('distribution', None)
                    event_report.pop('SharingGroup', None)
                    event_report.pop('sharing_group_id', None)
                to_return['EventReport'].append(event_report.to_dict())

        return {'Event': to_return}

    @property
    def known_types(self) -> list[str]:
        return self.describe_types['types']

    @property
    def org(self) -> MISPOrganisation:
        return self.Org

    @property
    def orgc(self) -> MISPOrganisation:
        return self.Orgc

    @orgc.setter
    def orgc(self, orgc: MISPOrganisation) -> None:
        if isinstance(orgc, MISPOrganisation):
            self.Orgc = orgc
        else:
            raise PyMISPError('Orgc must be of type MISPOrganisation.')

    @property
    def attributes(self) -> list[MISPAttribute]:
        return self.Attribute

    @attributes.setter
    def attributes(self, attributes: list[MISPAttribute]) -> None:
        if all(isinstance(x, MISPAttribute) for x in attributes):
            self.Attribute = attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPAttribute.')

    @property
    def event_reports(self) -> list[MISPEventReport]:
        return self.EventReport

    @property
    def shadow_attributes(self) -> list[MISPShadowAttribute]:
        return self.ShadowAttribute

    @shadow_attributes.setter
    def shadow_attributes(self, shadow_attributes: list[MISPShadowAttribute]) -> None:
        if all(isinstance(x, MISPShadowAttribute) for x in shadow_attributes):
            self.ShadowAttribute = shadow_attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPShadowAttribute.')

    @property
    def related_events(self) -> list[MISPEvent]:
        return self.RelatedEvent

    @property
    def galaxies(self) -> list[MISPGalaxy]:
        return self.Galaxy

    @galaxies.setter
    def galaxies(self, galaxies: list[MISPGalaxy]) -> None:
        if all(isinstance(x, MISPGalaxy) for x in galaxies):
            self.Galaxy = galaxies
        else:
            raise PyMISPError('All the attributes have to be of type MISPGalaxy.')

    @property
    def objects(self) -> list[MISPObject]:
        return self.Object

    @objects.setter
    def objects(self, objects: list[MISPObject]) -> None:
        if all(isinstance(x, MISPObject) for x in objects):
            self.Object = objects
        else:
            raise PyMISPError('All the attributes have to be of type MISPObject.')

    def load_file(self, event_path: Path | str, validate: bool = False, metadata_only: bool = False) -> None:
        """Load a JSON dump from a file on the disk"""
        if not os.path.exists(event_path):
            raise PyMISPError('Invalid path, unable to load the event.')
        with open(event_path, 'rb') as f:
            self.load(f, validate, metadata_only)

    def load(self, json_event: IO[bytes] | IO[str] | str | bytes | dict[str, Any], validate: bool = False, metadata_only: bool = False) -> None:
        """Load a JSON dump from a pseudo file or a JSON string"""
        if isinstance(json_event, (BufferedIOBase, TextIOBase)):
            json_event = json_event.read()

        if isinstance(json_event, (str, bytes)):
            json_event = json.loads(json_event)

        if isinstance(json_event, dict) and 'response' in json_event and isinstance(json_event['response'], list):
            event = json_event['response'][0]
        else:
            event = json_event
        if not event:
            raise PyMISPError('Invalid event')
        if metadata_only:
            event.pop('Attribute', None)
            event.pop('Object', None)
        self.from_dict(**event)
        if validate:
            warnings.warn('The validate parameter is deprecated because PyMISP is more flexible at loading event than the schema')

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ['date']:
            if isinstance(value, date):
                pass
            elif isinstance(value, str):
                try:
                    # faster
                    value = date.fromisoformat(value)
                except Exception:
                    value = parse(value).date()
            elif isinstance(value, (int, float)):
                value = date.fromtimestamp(value)
            elif isinstance(value, datetime):
                value = value.date()
            else:
                raise NewEventError(f'Invalid format for the date: {type(value)} - {value}')
        super().__setattr__(name, value)

    def set_date(self, d: str | int | float | datetime | date | None = None, ignore_invalid: bool = False) -> None:
        """Set a date for the event

        :param d: String, datetime, or date object
        :param ignore_invalid: if True, assigns current date if d is not an expected type
        """
        if isinstance(d, (str, int, float, datetime, date)):
            self.date = d  # type: ignore
        elif ignore_invalid:
            self.date = date.today()
        else:
            raise NewEventError(f'Invalid format for the date: {type(d)} - {d}')

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Event' in kwargs:
            kwargs = kwargs['Event']
        # Required value
        self.info = kwargs.pop('info', None)
        if self.info is None:
            raise NewEventError('The info field of the new event is required.')

        # Default values for a valid event to send to a MISP instance
        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4]:
                raise NewEventError(f'{self.info}: {self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4')

        if kwargs.get('threat_level_id') is not None:
            self.threat_level_id = int(kwargs.pop('threat_level_id'))
            if self.threat_level_id not in [1, 2, 3, 4]:
                raise NewEventError(f'{self.info}: {self.threat_level_id} is invalid, the threat_level_id has to be in 1, 2, 3, 4')

        if kwargs.get('analysis') is not None:
            self.analysis = int(kwargs.pop('analysis'))
            if self.analysis not in [0, 1, 2]:
                raise NewEventError(f'{self.info}: {self.analysis} is invalid, the analysis has to be in 0, 1, 2')

        self.published = kwargs.pop('published', None)
        if self.published is True:
            self.publish()
        else:
            self.unpublish()

        if kwargs.get('date'):
            self.set_date(kwargs.pop('date'))
        if kwargs.get('Attribute'):
            [self.add_attribute(**a) for a in kwargs.pop('Attribute')]
        if kwargs.get('Galaxy'):
            [self.add_galaxy(**e) for e in kwargs.pop('Galaxy')]
        if kwargs.get('EventReport'):
            [self.add_event_report(**e) for e in kwargs.pop('EventReport')]

        # All other keys
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('orgc_id'):
            self.orgc_id = int(kwargs.pop('orgc_id'))
        if kwargs.get('org_id'):
            self.org_id = int(kwargs.pop('org_id'))
        if kwargs.get('timestamp'):
            self.timestamp = datetime.fromtimestamp(int(kwargs.pop('timestamp')), timezone.utc)
        if kwargs.get('publish_timestamp'):
            self.publish_timestamp = datetime.fromtimestamp(int(kwargs.pop('publish_timestamp')), timezone.utc)
        if kwargs.get('sighting_timestamp'):
            self.sighting_timestamp = datetime.fromtimestamp(int(kwargs.pop('sighting_timestamp')), timezone.utc)
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))
        if kwargs.get('RelatedEvent'):
            for rel_event in kwargs.pop('RelatedEvent'):
                sub_event = MISPEvent()
                sub_event.load(rel_event)
                self.RelatedEvent.append({'Event': sub_event})  # type: ignore[arg-type]
        if kwargs.get('Tag'):
            [self.add_tag(tag) for tag in kwargs.pop('Tag')]
        if kwargs.get('Object'):
            [self.add_object(obj) for obj in kwargs.pop('Object')]
        if kwargs.get('Org'):
            self.Org = MISPOrganisation()
            self.Org.from_dict(**kwargs.pop('Org'))
        if kwargs.get('Orgc'):
            self.Orgc = MISPOrganisation()
            self.Orgc.from_dict(**kwargs.pop('Orgc'))
        if kwargs.get('SharingGroup'):
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))

        super().from_dict(**kwargs)

    def to_dict(self, json_format: bool = False) -> dict[str, Any]:
        to_return = super().to_dict(json_format)

        if to_return.get('date'):
            if isinstance(self.date, datetime):
                self.date = self.date.date()
            to_return['date'] = self.date.isoformat()
        if to_return.get('publish_timestamp'):
            to_return['publish_timestamp'] = str(self._datetime_to_timestamp(self.publish_timestamp))
        if to_return.get('sighting_timestamp'):
            to_return['sighting_timestamp'] = str(self._datetime_to_timestamp(self.sighting_timestamp))

        return to_return

    def add_proposal(self, shadow_attribute=None, **kwargs) -> MISPShadowAttribute:  # type: ignore[no-untyped-def]
        """Alias for add_shadow_attribute"""
        return self.add_shadow_attribute(shadow_attribute, **kwargs)

    def add_shadow_attribute(self, shadow_attribute=None, **kwargs) -> MISPShadowAttribute:  # type: ignore[no-untyped-def]
        """Add a tag to the attribute (by name or a MISPTag object)"""
        if isinstance(shadow_attribute, MISPShadowAttribute):
            misp_shadow_attribute = shadow_attribute
        elif isinstance(shadow_attribute, dict):
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**shadow_attribute)
        elif kwargs:
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**kwargs)
        else:
            raise PyMISPError(f"The shadow_attribute is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict[str, Any]): {shadow_attribute}")
        self.shadow_attributes.append(misp_shadow_attribute)
        self.edited = True
        return misp_shadow_attribute

    def get_attribute_tag(self, attribute_identifier: str) -> list[MISPTag]:
        """Return the tags associated to an attribute or an object attribute.

        :param attribute_identifier: can be an ID, UUID, or the value.
        """
        tags: list[MISPTag] = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and str(a.id) == attribute_identifier)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_identifier)
                    or (hasattr(a, 'value') and attribute_identifier == a.value
                        or (isinstance(a.value, str) and attribute_identifier in a.value.split('|')))):
                tags += a.tags
        return tags

    def add_attribute_tag(self, tag: MISPTag | str, attribute_identifier: str) -> list[MISPAttribute]:
        """Add a tag to an existing attribute. Raise an Exception if the attribute doesn't exist.

        :param tag: Tag name as a string, MISPTag instance, or dictionary
        :param attribute_identifier: can be an ID, UUID, or the value.
        """
        attributes = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and str(a.id) == attribute_identifier)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_identifier)
                    or (hasattr(a, 'value') and attribute_identifier == a.value
                        or (isinstance(a.value, str) and attribute_identifier in a.value.split('|')))):
                a.add_tag(tag)
                attributes.append(a)

        if not attributes:
            raise PyMISPError(f'No attribute with identifier {attribute_identifier} found.')
        self.edited = True
        return attributes

    def publish(self) -> None:
        """Mark the attribute as published"""
        self.published = True

    def unpublish(self) -> None:
        """Mark the attribute as un-published (set publish flag to false)"""
        self.published = False

    def delete_attribute(self, attribute_id: str) -> None:
        """Delete an attribute

        :param attribute_id: ID or UUID
        """
        for a in self.attributes:
            if ((hasattr(a, 'id') and str(a.id) == attribute_id)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_id)):
                a.delete()
                break
        else:
            raise PyMISPError(f'No attribute with UUID/ID {attribute_id} found.')

    def add_attribute(self, type: str, value: str | int | float, **kwargs) -> MISPAttribute | list[MISPAttribute]:  # type: ignore[no-untyped-def]
        """Add an attribute. type and value are required but you can pass all
        other parameters supported by MISPAttribute"""
        attr_list: list[MISPAttribute] = []
        if isinstance(value, list):
            attr_list = [self.add_attribute(type=type, value=a, **kwargs) for a in value]
        else:
            attribute = MISPAttribute(describe_types=self.describe_types)
            attribute.from_dict(type=type, value=value, **kwargs)
            self.attributes.append(attribute)
        self.edited = True
        if attr_list:
            return attr_list
        return attribute

    def add_event_report(self, name: str, content: str, **kwargs) -> MISPEventReport:  # type: ignore[no-untyped-def]
        """Add an event report. name and value are requred but you can pass all
        other parameters supported by MISPEventReport"""
        event_report = MISPEventReport()
        event_report.from_dict(name=name, content=content, **kwargs)
        self.event_reports.append(event_report)
        self.edited = True
        return event_report

    def add_galaxy(self, galaxy: MISPGalaxy | dict[str, Any] | None = None, **kwargs) -> MISPGalaxy:  # type: ignore[no-untyped-def]
        """Add a galaxy and sub-clusters into an event, either by passing
        a MISPGalaxy or a dictionary.
        Supports all other parameters supported by MISPGalaxy"""
        if isinstance(galaxy, MISPGalaxy):
            self.galaxies.append(galaxy)
            return galaxy
        if isinstance(galaxy, dict):
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**galaxy)
        elif kwargs:
            misp_galaxy = MISPGalaxy()
            misp_galaxy.from_dict(**kwargs)
        else:
            raise InvalidMISPGalaxy("A Galaxy to add to an existing Event needs to be either a MISPGalaxy or a plain python dictionary")
        self.galaxies.append(misp_galaxy)
        return misp_galaxy

    def get_attribute_by_id(self, attribute_id: str | int) -> MISPAttribute:
        """Get an attribute by ID

        :param attribute_id: The ID of the seeking attribute"""
        for attribute in self.attributes:
            if hasattr(attribute, 'id') and int(attribute.id) == int(attribute_id):
                return attribute
        raise InvalidMISPAttribute(f'Attribute with {attribute_id} does not exist in this event')

    def get_attribute_by_uuid(self, attribute_uuid: str) -> MISPAttribute:
        """Get an attribute by UUID

        :param attribute_uuid: The UUID of the seeking attribute"""
        for attribute in self.attributes:
            if hasattr(attribute, 'uuid') and attribute.uuid == attribute_uuid:
                return attribute

        raise InvalidMISPAttribute(f'Attribute with {attribute_uuid} does not exist in this event')

    def get_object_by_id(self, object_id: str | int) -> MISPObject:
        """Get an object by ID

        :param object_id: the ID is the one set by the server when creating the new object"""
        for obj in self.objects:
            if hasattr(obj, 'id') and int(obj.id) == int(object_id):
                return obj
        raise InvalidMISPObject(f'Object with {object_id} does not exist in this event')

    def get_object_by_uuid(self, object_uuid: str) -> MISPObject:
        """Get an object by UUID

        :param object_uuid: the UUID is set by the server when creating the new object"""
        for obj in self.objects:
            if hasattr(obj, 'uuid') and obj.uuid == object_uuid:
                return obj
        raise InvalidMISPObject(f'Object with {object_uuid} does not exist in this event')

    def get_objects_by_name(self, object_name: str) -> list[MISPObject]:
        """Get objects by name

        :param object_name: name is set by the server when creating the new object"""
        objects = []
        for obj in self.objects:
            if hasattr(obj, 'uuid') and obj.name == object_name:
                objects.append(obj)
        return objects

    def add_object(self, obj: MISPObject | dict[str, Any] | None = None, **kwargs) -> MISPObject:  # type: ignore[no-untyped-def]
        """Add an object to the Event, either by passing a MISPObject, or a dictionary"""
        if isinstance(obj, MISPObject):
            misp_obj = obj
        elif isinstance(obj, dict):
            misp_obj = MISPObject(name=obj.pop('name'), strict=obj.pop('strict', False),
                                  default_attributes_parameters=obj.pop('default_attributes_parameters', {}),
                                  **obj)
            misp_obj.from_dict(**obj)
        elif kwargs:
            misp_obj = MISPObject(name=kwargs.pop('name'), strict=kwargs.pop('strict', False),
                                  default_attributes_parameters=kwargs.pop('default_attributes_parameters', {}),
                                  **kwargs)
            misp_obj.from_dict(**kwargs)
        else:
            raise InvalidMISPObject("An object to add to an existing Event needs to be either a MISPObject, or a plain python dictionary")
        misp_obj.standalone = False
        self.Object.append(misp_obj)
        self.edited = True
        return misp_obj

    def delete_object(self, object_id: str) -> None:
        """Delete an object

        :param object_id: ID or UUID
        """
        for o in self.objects:
            if ((hasattr(o, 'id') and object_id.isdigit() and int(o.id) == int(object_id))
                    or (hasattr(o, 'uuid') and o.uuid == object_id)):
                o.delete()
                break
        else:
            raise PyMISPError(f'No object with UUID/ID {object_id} found.')

    def run_expansions(self) -> None:
        for index, attribute in enumerate(self.attributes):
            if 'expand' not in attribute:
                continue
            # NOTE: Always make sure the attribute with the expand key is either completely removed,
            # of the key is deleted to avoid seeing it processed again on MISP side
            elif attribute.expand == 'binary':
                try:
                    from .tools import make_binary_objects
                except ImportError as e:
                    logger.info(f'Unable to load make_binary_objects: {e}')
                    continue
                file_object, bin_type_object, bin_section_objects = make_binary_objects(pseudofile=attribute.malware_binary, filename=attribute.malware_filename)
                self.add_object(file_object)
                if bin_type_object:
                    self.add_object(bin_type_object)
                if bin_section_objects:
                    for bin_section_object in bin_section_objects:
                        self.add_object(bin_section_object)
                self.attributes.pop(index)
            else:
                logger.warning(f'No expansions for this data type ({attribute.type}). Open an issue if needed.')

    def __repr__(self) -> str:
        if hasattr(self, 'info'):
            return '<{self.__class__.__name__}(info={self.info})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPObjectTemplate(AbstractMISP):

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'ObjectTemplate' in kwargs:
            kwargs = kwargs['ObjectTemplate']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(self.name)'


class MISPUser(AbstractMISP):

    authkey: str

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.email: str
        self.password: str | None

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'User' in kwargs:
            kwargs = kwargs['User']
        super().from_dict(**kwargs)
        if hasattr(self, 'password') and self.password and set(self.password) == {'*', }:
            self.password = None

    def __repr__(self) -> str:
        if hasattr(self, 'email'):
            return '<{self.__class__.__name__}(email={self.email})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPFeed(AbstractMISP):

    settings: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Feed' in kwargs:
            kwargs = kwargs['Feed']
        super().from_dict(**kwargs)
        if hasattr(self, 'settings'):
            try:
                self.settings = json.loads(self.settings)
            except json.decoder.JSONDecodeError as e:
                logger.error(f"Failed to parse feed settings: {self.settings}")
                raise e


class MISPWarninglist(AbstractMISP):

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Warninglist' in kwargs:
            kwargs = kwargs['Warninglist']
        super().from_dict(**kwargs)


class MISPTaxonomy(AbstractMISP):

    enabled: bool
    namespace: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Taxonomy' in kwargs:
            kwargs = kwargs['Taxonomy']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(namespace={self.namespace})>'


class MISPNoticelist(AbstractMISP):

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Noticelist' in kwargs:
            kwargs = kwargs['Noticelist']
        super().from_dict(**kwargs)


class MISPCorrelationExclusion(AbstractMISP):

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'CorrelationExclusion' in kwargs:
            kwargs = kwargs['CorrelationExclusion']
        super().from_dict(**kwargs)


class MISPRole(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.name: str
        self.perm_add: bool
        self.perm_modify: bool
        self.perm_modify_org: bool
        self.perm_publish: bool
        self.perm_delegate: bool
        self.perm_sync: bool
        self.perm_admin: bool
        self.perm_audit: bool
        self.perm_auth: bool
        self.perm_site_admin: bool
        self.perm_regexp_access: bool
        self.perm_tagger: bool
        self.perm_template: bool
        self.perm_sharing_group: bool
        self.perm_tag_editor: bool
        self.perm_sighting: bool
        self.perm_object_template: bool
        self.default_role: bool
        self.memory_limit: str | int
        self.max_execution_time: str | int
        self.restricted_to_site_admin: bool
        self.perm_publish_zmq: bool
        self.perm_publish_kafka: bool
        self.perm_decaying: bool
        self.enforce_rate_limit: bool
        self.rate_limit_count: str | int
        self.perm_galaxy_editor: bool
        self.perm_warninglist: bool
        self.perm_view_feed_correlations: bool
        self.perm_analyst_data: bool
        self.permission: str
        self.permission_description: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Role' in kwargs:
            kwargs = kwargs['Role']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return '<{self.__class__.__name__}({self.name})'.format(self=self)


class MISPServer(AbstractMISP):

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Server' in kwargs:
            kwargs = kwargs['Server']
        super().from_dict(**kwargs)


class MISPLog(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.model: str
        self.action: str
        self.title: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Log' in kwargs:
            kwargs = kwargs['Log']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return '<{self.__class__.__name__}({self.model}, {self.action}, {self.title})'.format(self=self)


class MISPEventDelegation(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.org_id: int
        self.requester_org_id: int
        self.event_id: int

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'EventDelegation' in kwargs:
            kwargs = kwargs['EventDelegation']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return '<{self.__class__.__name__}(org_id={self.org_id}, requester_org_id={self.requester_org_id}, {self.event_id})'.format(self=self)


class MISPObjectAttribute(MISPAttribute):

    _fields_for_feed: set[str] = {'uuid', 'value', 'category', 'type', 'comment', 'data',
                                  'deleted', 'timestamp', 'to_ids', 'disable_correlation',
                                  'first_seen', 'last_seen', 'object_relation'}

    def __init__(self, definition: dict[str, Any]) -> None:
        super().__init__()
        self._definition = definition

    def from_dict(self, object_relation: str, value: str | int | float, **kwargs):  # type: ignore
        # NOTE: Signature of "from_dict" incompatible with supertype "MISPAttribute"
        self.object_relation = object_relation
        self.value = value
        if 'Attribute' in kwargs:
            kwargs = kwargs['Attribute']
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = self._definition.get('misp-attribute')
        if 'category' not in kwargs and 'categories' in self._definition:
            # Get first category in the list from the object template as default
            self.category = self._definition['categories'][0]
        self.disable_correlation = kwargs.pop('disable_correlation', None)
        if self.disable_correlation is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            self.disable_correlation = self._definition.get('disable_correlation')
        self.to_ids = kwargs.pop('to_ids', None)
        if self.to_ids is None:
            # Same for the to_ids flag
            self.to_ids = self._definition.get('to_ids')
        if not self.type:
            raise NewAttributeError("The type of the attribute is required. Is the object template missing?")
        super().from_dict(**{**self, **kwargs})

    def __repr__(self) -> str:
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(object_relation={self.object_relation}, value={self.value})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPCommunity(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.name: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Community' in kwargs:
            kwargs = kwargs['Community']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(name={self.name}, uuid={self.uuid})'


class MISPUserSetting(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.setting: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'UserSetting' in kwargs:
            kwargs = kwargs['UserSetting']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(name={self.setting}'


class MISPInbox(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.data: dict[str, Any]
        self.type: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Inbox' in kwargs:
            kwargs = kwargs['Inbox']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(name={self.type})>'


class MISPEventBlocklist(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.event_uuid: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'EventBlocklist' in kwargs:
            kwargs = kwargs['EventBlocklist']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(event_uuid={self.event_uuid}'


class MISPOrganisationBlocklist(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.org_uuid: str

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'OrgBlocklist' in kwargs:
            kwargs = kwargs['OrgBlocklist']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(org_uuid={self.org_uuid}'


class MISPDecayingModel(AbstractMISP):

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.uuid: str
        self.id: int

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'DecayingModel' in kwargs:
            kwargs = kwargs['DecayingModel']
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(uuid={self.uuid})>'


class MISPAnalystData(AbstractMISP):

    _fields_for_feed: set[str] = {'uuid', 'object_uuid', 'object_type', 'authors',
                                  'created', 'distribution', 'sharing_group_id', 'note_type_name'}

    valid_object_type = {'Attribute', 'Event', 'EventReport', 'GalaxyCluster', 'Galaxy',
                         'Object', 'Note', 'Opinion', 'Relationship', 'Organisation',
                         'SharingGroup'}

    @property
    def org(self) -> MISPOrganisation:
        return self.Org

    @property
    def orgc(self) -> MISPOrganisation:
        return self.Orgc

    @orgc.setter
    def orgc(self, orgc: MISPOrganisation) -> None:
        if isinstance(orgc, MISPOrganisation):
            self.Orgc = orgc
        else:
            raise PyMISPError('Orgc must be of type MISPOrganisation.')

    def __new__(cls, *args, **kwargs):
        if cls is MISPAnalystData:
            raise TypeError(f"only children of '{cls.__name__}' may be instantiated")
        return object.__new__(cls)

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(**kwargs)
        self.uuid = str(uuid.uuid4())
        self.object_uuid: str
        self.object_type: str
        self.authors: str
        self.created: float | int | datetime
        self.modified: float | int | datetime
        self.SharingGroup: MISPSharingGroup

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAnalystDataError(f'{self.distribution} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5')

        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewAnalystDataError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewAnalystDataError(f'If the distribution is set to sharing group, a sharing group ID is required (cannot be {self.sharing_group_id}).')

        self.object_uuid = kwargs.pop('object_uuid', None)
        if self.object_uuid is None:
            raise NewAnalystDataError('The UUID for which this element is attached is required.')
        self.object_type = kwargs.pop('object_type', None)
        if self.object_type is None:
            raise NewAnalystDataError('The element type for which this element is attached is required.')
        if self.object_type not in self.valid_object_type:
            raise NewAnalystDataError('The element type is not a valid type. Actual: {self.object_type}.')

        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('created'):
            ts = kwargs.pop('created')
            if isinstance(ts, datetime):
                self.created = ts
            else:
                self.created = datetime.fromisoformat(ts + '+00:00')  # Force UTC TZ
        if kwargs.get('modified'):
            ts = kwargs.pop('modified')
            if isinstance(ts, datetime):
                self.modified = ts
            else:
                self.modified = datetime.fromisoformat(ts + '+00:00')  # Force UTC TZ

        if kwargs.get('Org'):
            self.Org = MISPOrganisation()
            self.Org.from_dict(**kwargs.pop('Org'))
        if kwargs.get('Orgc'):
            self.Orgc = MISPOrganisation()
            self.Orgc.from_dict(**kwargs.pop('Orgc'))
        if kwargs.get('SharingGroup'):
            self.SharingGroup = MISPSharingGroup()
            self.SharingGroup.from_dict(**kwargs.pop('SharingGroup'))

        super().from_dict(**kwargs)

    def _set_default(self) -> None:
        if not hasattr(self, 'created'):
            self.created = datetime.timestamp(datetime.now())
        if not hasattr(self, 'modified'):
            self.modified = self.created


class MISPNote(AnalystDataBehaviorMixin, MISPAnalystData):

    _fields_for_feed: set[str] = MISPAnalystData._fields_for_feed.union({'note', 'language'})

    _analyst_data_object_type = 'Note'

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        self.note: str
        self.language: str
        super().__init__(**kwargs)

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Note' in kwargs:
            kwargs = kwargs['Note']
        self.note = kwargs.pop('note', None)
        if self.note is None:
            raise NewNoteError('The text note of the note is required.')
        super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'note'):
            return '<{self.__class__.__name__}(note={self.note})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPOpinion(AnalystDataBehaviorMixin, MISPAnalystData):

    _fields_for_feed: set[str] = MISPAnalystData._fields_for_feed.union({'opinion', 'comment'})

    _analyst_data_object_type = 'Opinion'

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        self.opinion: int
        self.comment: str
        super().__init__(**kwargs)

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Opinion' in kwargs:
            kwargs = kwargs['Opinion']
        self.opinion = kwargs.pop('opinion', None)
        if self.opinion is not None:
            self.opinion = int(self.opinion)
            if not (0 <= self.opinion <= 100):
                raise NewOpinionError('The opinion value must be between 0 and 100 included.')
        else:
            raise NewOpinionError('The opinion value is required.')

        self.comment = kwargs.pop('comment', None)
        if self.comment is None:
            raise NewOpinionError('The text comment is required.')

        return super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'opinion'):
            return '<{self.__class__.__name__}([opinion={self.opinion}] comment={self.comment})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'


class MISPRelationship(AnalystDataBehaviorMixin, MISPAnalystData):

    _fields_for_feed: set[str] = MISPAnalystData._fields_for_feed.union({'related_object_uuid', 'related_object_type', 'relationship_type'})

    _analyst_data_object_type = 'Relationship'

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        self.related_object_uuid: str
        self.related_object_type: str
        self.relationship_type: str
        super().__init__(**kwargs)

    def from_dict(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if 'Relationship' in kwargs:
            kwargs = kwargs['Relationship']
        self.related_object_type = kwargs.pop('related_object_type', None)
        if self.related_object_type is None:
            raise NewRelationshipError('The target object type for this relationship is required.')

        self.related_object_uuid = kwargs.pop('related_object_uuid', None)
        if self.related_object_uuid is None:
            if not isinstance(self.related_object_type, AbstractMISP):
                raise NewRelationshipError('The target UUID for this relationship is required.')
            else:
                self.related_object_uuid = self.related_object_type.uuid
                self.related_object_type = self.related_object_type._analyst_data_object_type

        if self.related_object_type not in self.valid_object_type:
            raise NewAnalystDataError(f'The target object type is not a valid type. Actual: {self.related_object_type}.')

        return super().from_dict(**kwargs)

    def __repr__(self) -> str:
        if hasattr(self, 'related_object_uuid') and hasattr(self, 'object_uuid'):
            return '<{self.__class__.__name__}(object_uuid={self.object_uuid}, related_object_type={self.related_object_type}, related_object_uuid={self.related_object_uuid}, relationship_type={self.relationship_type})'.format(self=self)
        return f'<{self.__class__.__name__}(NotInitialized)'
