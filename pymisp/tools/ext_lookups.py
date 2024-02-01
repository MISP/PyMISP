#!/usr/bin/env python

from __future__ import annotations

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


def revert_tag_from_galaxies(tag: str) -> list[str]:
    clusters = Clusters()
    try:
        return clusters.revert_machinetag(tag)
    except Exception:
        return []


def revert_tag_from_taxonomies(tag: str) -> list[str]:
    taxonomies = Taxonomies()
    try:
        return taxonomies.revert_machinetag(tag)
    except Exception:
        return []


def search_taxonomies(query: str) -> list[str]:
    taxonomies = Taxonomies()
    found = taxonomies.search(query)
    if not found:
        found = taxonomies.search(query, expanded=True)
    return found


def search_galaxies(query: str) -> list[str]:
    clusters = Clusters()
    return clusters.search(query)
