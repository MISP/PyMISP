#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from pymispgalaxies import Clusters  # type: ignore
    has_pymispgalaxies = True
except ImportError:
    has_pymispgalaxies = False

try:
    from pytaxonomies import Taxonomies  # type: ignore
    has_pymispgalaxies = True
except ImportError:
    has_pymispgalaxies = False


def revert_tag_from_galaxies(tag):
    clusters = Clusters()
    try:
        return clusters.revert_machinetag(tag)
    except Exception:
        return []


def revert_tag_from_taxonomies(tag):
    taxonomies = Taxonomies()
    try:
        return taxonomies.revert_machinetag(tag)
    except Exception:
        return []


def search_taxonomies(query):
    taxonomies = Taxonomies()
    found = taxonomies.search(query)
    if not found:
        found = taxonomies.search(query, expanded=True)
    return found


def search_galaxies(query):
    clusters = Clusters()
    return clusters.search(query)
