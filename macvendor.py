# This file parses the MAC file and allow us to efficiently retrieve the vendor of a MAC
# Part of this file was copied from https://github.com/coolbho3k/manuf

from collections import namedtuple
import re
import os
import io
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# Vendor tuple
Vendor = namedtuple('Vendor', ['manuf', 'manuf_long', 'comment'])
_masks = {}


def refresh():
    global _masks
    """Refresh/reload manuf database. Call this when manuf file is updated.
    Args:
        fname (str): Location of the manuf data base file. Defaults to "manuf" in the
            same directory.
    Raises:
        IOError: If manuf file could not be found.
    """
    fname='oui.txt'
    with io.open(fname, "r", encoding="utf-8") as read_file:
        ffile = StringIO(read_file.read())

    # Build mask -> result dict
    for line in ffile:
        try:
            line = line.strip()
            if not line or line[0] == "#":
                continue
            line = line.replace("\t\t", "\t")
            fields = [field.strip() for field in line.split("\t")]

            parts = fields[0].split("/")
            mac_str = _strip_mac(parts[0])
            mac_int = _get_mac_int(mac_str)
            mask = _bits_left(mac_str)

            # Specification includes mask
            if len(parts) > 1:
                mask_spec = 48 - int(parts[1])
                if mask_spec > mask:
                    mask = mask_spec

            comment = fields[3].strip("#").strip() if len(fields) > 3 else None
            long_name = fields[2] if len(fields) > 2 else None

            _masks[(mask, mac_int >> mask)] = Vendor(manuf=fields[1], manuf_long=long_name, comment=comment)
        except:
            print("Couldn't parse line", line)
            raise

    ffile.close()

def _get_mac_int(mac_str):
    # Gets the integer representation of a stripped mac string
    try:
        # Fill in missing bits with zeroes
        return int(mac_str, 16) << _bits_left(mac_str)
    except ValueError:
        raise ValueError("Could not parse MAC: {0}".format(mac_str))


def _strip_mac(mac):
    # Strips the MAC address of '-', ':', and '.' characters
    # Regular expression that matches '-', ':', and '.' characters
    _pattern = re.compile(r"[-:\.]")
    return _pattern.sub("", mac)

def _bits_left(mac_str):
    # Gets the number of bits left in a mac string
    return 48 - 4 * len(mac_str)



def search(mac, maximum=1):
    global _masks
    """Search for multiple Vendor tuples possibly matching a MAC address.

    Args:
        mac (str): MAC address in standard format.
        maximum (int): Maximum results to return. Defaults to 1.

    Returns:
        List of Vendor namedtuples containing (manuf, comment), with closest result first. May
        be empty if no results found.

    Raises:
        ValueError: If the MAC could not be parsed.

    """
    vendors = []
    if maximum <= 0:
        return vendors
    mac_str = _strip_mac(mac)
    mac_int = _get_mac_int(mac_str)

    # If the user only gave us X bits, check X bits. No partial matching!
    for mask in range(_bits_left(mac_str), 48):
        result = _masks.get((mask, mac_int >> mask))
        if result:
            vendors.append(result)
            if len(vendors) >= maximum:
                break
    return vendors

def get_all(mac):
    """Get a Vendor tuple containing (manuf, comment) from a MAC address.

    Args:
        mac (str): MAC address in standard format.

    Returns:
        Vendor: Vendor namedtuple containing (manuf, comment). Either or both may be None if
        not found.

    Raises:
        ValueError: If the MAC could not be parsed.

    """
    vendors = search(mac)
    if len(vendors) == 0:
        return Vendor(manuf=None, manuf_long=None, comment=None)
    return vendors[0]

def get_manuf(mac):
    """Returns manufacturer from a MAC address.

    Args:
        mac (str): MAC address in standard format.

    Returns:
        string: String containing manufacturer, or None if not found.

    Raises:
        ValueError: If the MAC could not be parsed.

    """
    return get_all(mac).manuf

def get_manuf_long(mac):
    """Returns manufacturer long name from a MAC address.

    Args:
        mac (str): MAC address in standard format.

    Returns:
        string: String containing manufacturer, or None if not found.

    Raises:
        ValueError: If the MAC could not be parsed.

    """
    return get_all(mac).manuf_long

def get_comment(mac):
    """Returns comment from a MAC address.

    Args:
        mac (str): MAC address in standard format.

    Returns:
        string: String containing comment, or None if not found.

    Raises:
        ValueError: If the MAC could not be parsed.

    """
    return get_all(mac).comment



# Example
#if __name__ == "__main__":
#    refresh()
#    vendor=get_all('f8:38:80:ed:9d:e8'.upper())
#    print(vendor)