from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

import yaml

from .policy import PolicyError


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PolicyError("DUPLICATE_YAML_KEY", f"Duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_policy_bundle(
    path: Union[str, Path]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    with Path(path).open("r", encoding="utf-8") as stream:
        document = yaml.load(stream, Loader=UniqueKeyLoader)
    if not isinstance(document, dict):
        raise PolicyError("INVALID_FIXTURE", "Policy bundle must be a YAML mapping")
    context = document.get("context")
    proposals = document.get("proposals")
    if not isinstance(context, dict) or not isinstance(proposals, list):
        raise PolicyError(
            "INVALID_FIXTURE", "Policy bundle requires context and proposals"
        )
    # Copy each proposal independently so YAML anchors cannot create mutable
    # references shared across participant inputs.
    return copy.deepcopy(context), [copy.deepcopy(proposal) for proposal in proposals]
