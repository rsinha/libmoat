import socket
import sys
import pickle
import struct
from binascii import hexlify, unhexlify

import json
import Crypto
from Crypto.PublicKey import RSA


def to_json_string(obj):
    """Convert basic Python objects into a JSON-serialized string.

    Because our Crypto API operates on strings, this can be useful
    for converting objects like lists or dictionaries into
    string format, instead of deriving your own data format.

    This function can correctly handle serializing RSA key objects.

    This uses the JSON library to dump the object to a string. For more
    information on JSON in Python, see the `JSON library
    <https://docs.python.org/3/library/json.html>`_ in the Python standard
    library.

    This function makes sure that the order of keys in a JSON is deterministic
    (it always serializes the same data in the same way).
    If you decide to use your own serialization make sure it is deterministic as well.

    :param obj: A JSON-serializable Python object
    :returns: A JSON-serialized string for `obj`

    :raises TypeError: If `obj` isn't JSON serializable.
    """
    class RSAEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Crypto.PublicKey.RSA._RSAobj):
                return {'__type__': '_RSAobj', 'PEMdata':
                        str(obj.exportKey(format='PEM'), 'utf-8')}
            return json.JSONEncoder.default(self, obj)
    return json.dumps(obj, cls=RSAEncoder, sort_keys=True)


def from_json_string(s):
    """Convert a JSON string back into a basic Python object.

    This function can correctly handle deserializing back into RSA key objects.

    This uses the JSON library to load the object from a string.
    For more information on JSON in Python, see the `JSON library
    <https://docs.python.org/3/library/json.html>`_ in the Python standard
    library.

    :param str s: A JSON string
    :returns: The Python object deserialized from `s`

    :raises JSONDecodeError: If `s` is not a valid JSON document.
    :raises TypeError: If `s` isn't a string.
    """
    def RSA_decoder(obj):
        if '__type__' in obj and obj['__type__'] == '_RSAobj':
            return RSA.importKey(obj['PEMdata'])
        return obj
    return json.loads(s, object_hook=RSA_decoder)


def compute_edits(old, new):
    """Compute the in-place edits needed to convert from old to new

    Returns a list ``[(index_1,change_1), (index_2,change_2)...]``
    where ``index_i`` is an offset into old, and ``change_1`` is the
    new bytes to replace.

    For example, calling ``compute_edits("abcdef", "qbcdzw")`` will return
    ``[(0, "q"), (4, "zw")]``.

    That is, the update should be preformed as (abusing notation):

    ``new[index:index+len(change)] = change``

    :param str old: The old data
    :param str new: The new data

    :returns: A list of tuples (index_i, change_i)
    """
    deltas = []
    delta = None
    for index, (n, o) in enumerate(zip(new, old)):
        if n == o:
            if delta is not None:
                deltas.append(delta)
                delta = None
        else:
            if delta is None:
                delta = (index, [])
            delta[1].append(n)

    if delta is not None:
        deltas.append(delta)

    return [(i, "".join(x)) for i, x in deltas]
