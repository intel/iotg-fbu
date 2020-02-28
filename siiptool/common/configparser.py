from collections.abc import MutableMapping
import warnings
import json
from configparser import *
from configparser import __all__

__all__.append("JSONConfigParser")

_ConfigParser = ConfigParser


class ConfigParser:
    """Accepts extra keyword config_type and returns the instance based on it"""
    def __new__(cls, *args, **kwds):
        config_type = kwds.pop("config_type", "ini")
        if config_type == "json":
            return JSONConfigParser()
        return _ConfigParser(*args, **kwds)


class JSONConfigParser(MutableMapping):
    """A ConfigParser that works with json file."""
    def __init__(self):
        self._dict = {}

    def defaults(self):
        raise NotImplementedError

    def sections(self):
        """Return a list of section names"""
        return list(self._dict)

    def add_section(self, section):
        """Create a new section in the configuration.

        Raise DuplicateSectionError if a section by the specified name
        already exists.
        """
        if self.has_section(section):
            raise DuplicateSectionError(section)
        self._dict[section] = {}

    def has_section(self, section):
        """Indicate whether the named section is present in the configuration."""
        if section in self._dict:
            return True
        return False

    def options(self, section):
        """Return a list of option names for the given section name."""
        try:
            return list(self._dict[section])
        except KeyError as e:
            raise NoSectionError(str(e)) from None

    def read(self, filenames, encoding=None):
        """Read and parse a filename or a list of filenames.

        Files that cannot be opened are silently ignored; this is
        designed so that you can specify a list of potential
        configuration file locations (e.g. current directory, user's
        home directory, systemwide directory), and all existing
        configuration files in the list will be read.  A single
        filename may also be given.

        Return list of successfully read files.
        """
        if isinstance(filenames, str):
            filenames = [filenames]
        read_ok = []
        for filename in filenames:
            try:
                with open(filename, encoding=encoding) as f:
                    self.read_file(f)
            except OSError:
                continue
            read_ok.append(filename)
        return read_ok

    def read_file(self, f, **kwds):
        """Like read() but the argument must be a file-like object.

        The 'f' argument must be a json document.
        """
        dictionary = json.load(f)
        self.read_dict(dictionary)

    def read_string(self, string, **kwds):
        """Read configuration from a given string that contain json document."""
        self._dict.update(json.loads(string))

    def read_dict(self, dictionary, **kwds):
        """Read configuration from a dictionary."""
        self._dict.update(dictionary)

    def readfp(self, fp, **kwds):
        """Deprecated, use read_file instead."""
        warnings.warn(
            "This method will be removed in future versions.  "
            "Use 'parser.read_file()' instead.",
            DeprecationWarning, stacklevel=2
        )
        self.read_file(fp, **kwds)
        pass

    def has_option(self, section, option):
        """Check for the existence of a given option in a given section."""
        try:
            if option in self._dict[section]:
                return True
            return False
        except KeyError as e:
            raise NoSectionError(str(e)) from None

    def set(self, section, option, value=None):
        """Set an option."""
        self._dict[section][option] = value

    def write(self, fp, **kwds):
        """Write an .json-format representation of the configuration state."""
        json.dump(self._dict, fp)

    def remove_option(self, section, option):
        """Remove an option."""
        try:
            del(self._dict[section][option])
        except KeyError as e:
            if str(e) == section:
                raise NoSectionError(section) from None
            else:
                raise NoOptionError(option) from None

    def remove_section(self, section):
        """Remove a file section."""
        try:
            del(self._dict[section])
        except KeyError:
            raise NoSectionError(section) from None

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        self._dict[key] = value

    def __delitem__(self, key):
        del(self._dict[key])

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict.keys)

    # These methods provided directly for campatibility with orginal ConfigParser
    def getint(self, section, option, **kwds):
        try:
            return int(self._dict[section][option])
        except KeyError as e:
            error_key = str(e)
            if error_key == section:
                raise NoSectionError(error_key) from None
            else:
                raise NoOptionError(error_key) from None

    def getfloat(self, section, option, **kwds):
        try:
            return float(self._dict[section][option])
        except KeyError as e:
            error_key = str(e)
            if error_key == section:
                raise NoSectionError(error_key) from None
            else:
                raise NoOptionError(error_key) from None

    def getboolean(self, section, option, **kwds):
        try:
            val = self._dict[section][option]
            if isinstance(val, bool):
                return val
            raise ValueError("value is not boolean")
        except KeyError as e:
            error_key = str(e)
            if error_key == section:
                raise NoSectionError(error_key) from None
            else:
                raise NoOptionError(error_key) from None

    # To do:implement for this class
    def optionxform(self, optionstr):
        raise NotImplementedError

    @property
    def converters(self):
        raise NotImplementedError
