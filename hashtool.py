#!/usr/bin/python

# HashTool - A simple GUI application to generate hashes for arbitrary strings
# Copyright (C) 2014 Marko Silokunnas
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import zlib
from Crypto.Hash import MD2, MD4, MD5, SHA, SHA224, SHA256, SHA384, SHA512, RIPEMD, HMAC
import binascii
import base64

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class Hasher:
    hashfuncs = {}

    def __init__(self):
        self.hashfuncs["md2"] = self._hashMD2
        self.hashfuncs["md4"] = self._hashMD4
        self.hashfuncs["md5"] = self._hashMD5
        self.hashfuncs["sha"] = self._hashSHA
        self.hashfuncs["sha224"] = self._hashSHA224
        self.hashfuncs["sha256"] = self._hashSHA256
        self.hashfuncs["sha384"] = self._hashSHA384
        self.hashfuncs["sha512"] = self._hashSHA512
        self.hashfuncs["ripemd"] = self._hashRIPEMD

    def Hash(self, hashfunc, value, hmacKey=None):
        return self.hashfuncs[hashfunc](value, hmacKey)

    def _hashMD2(self, value, hmacKey):
        return self._cryptolibwrapper(MD2, value, hmacKey)

    def _hashMD4(self, value, hmacKey):
        return self._cryptolibwrapper(MD4, value, hmacKey)

    def _hashMD5(self, value, hmacKey):
        return self._cryptolibwrapper(MD5, value, hmacKey)

    def _hashSHA(self, value, hmacKey):
        return self._cryptolibwrapper(SHA, value, hmacKey)

    def _hashSHA224(self, value, hmacKey):
        return self._cryptolibwrapper(SHA224, value, hmacKey)

    def _hashSHA256(self, value, hmacKey):
        return self._cryptolibwrapper(SHA256, value, hmacKey)

    def _hashSHA384(self, value, hmacKey):
        return self._cryptolibwrapper(SHA384, value, hmacKey)

    def _hashSHA512(self, value, hmacKey):
        return self._cryptolibwrapper(SHA512, value, hmacKey)

    def _hashRIPEMD(self, value, hmacKey):
        return self._cryptolibwrapper(RIPEMD, value, hmacKey)

    def _cryptolibwrapper(self, alg, value, hmacKey=None):
        if hmacKey == None:
            return alg.new(value).hexdigest()

        h = HMAC.new(str(hmacKey), digestmod=alg)
        h.update(value)
        return h.hexdigest()


class MainWindowHandler:


    def __init__(self, builder):
        self.builder = builder
        self.hasher = Hasher()

        self.input_type = "ASCII"
        self.hmac_type = "ASCII"

        # a map of tuples that contain the entry and the associated hashing
        # function. Key is the name of the hashing algorithm.
        self.entries = {
            "md2":    (builder.get_object("entry_md2"), self.hasher._hashMD2),
            "md4":    (builder.get_object("entry_md4"), self.hasher._hashMD4),
            "md5":    (builder.get_object("entry_md5"), self.hasher._hashMD5),
            "sha":    (builder.get_object("entry_sha"), self.hasher._hashSHA),
            "sha224": (builder.get_object("entry_sha224"), self.hasher._hashSHA224),
            "sha256": (builder.get_object("entry_sha256"), self.hasher._hashSHA256),
            "sha384": (builder.get_object("entry_sha384"), self.hasher._hashSHA384),
            "sha512": (builder.get_object("entry_sha512"), self.hasher._hashSHA512),
            "ripemd": (builder.get_object("entry_ripemd"), self.hasher._hashRIPEMD),
        }


    def onCloseApplication(self, *args):
        Gtk.main_quit(*args)


    def onHMACChanged(self, hmac_entry):
        self._calculateHashes()


    def onInputChanged(self, entry_input):
        self._calculateHashes()


    def onInputTypeChanged(self, combobox_input_type):
        input_type_index = combobox_input_type.get_active()
        input_type_model = combobox_input_type.get_model()
        self.input_type = input_type_model[input_type_index][0]

        self._calculateHashes()


    def onHMACTypeChanged(self, combobox_hmac_type):
        hmac_type_index = combobox_hmac_type.get_active()
        hmac_type_model = combobox_hmac_type.get_model()
        self.hmac_type = hmac_type_model[hmac_type_index][0]

        self._calculateHashes()


    def _calculateHashes(self):
        entry_input = self.builder.get_object("entry_input")
        entry_hmac = self.builder.get_object("entry_hmac")

        input_type = self.input_type
        hmac_type = self.hmac_type

        input_text = entry_input.get_text()
        hmac = None
        if entry_hmac.get_text() != "":
            hmac = entry_hmac.get_text()

        try:
            if input_type != "ASCII":
                input_text = self._convertText(input_text, input_type)
            if hmac_type != "ASCII" and hmac is not None:
                hmac = self._convertText(hmac, hmac_type)
        except TypeError as e:
            # if we don't do this the program won't quit cleanly for some
            # reason if there have been any exceptions.
            pass

        for _,(entry, f) in self.entries.iteritems():

            if input_text == "":
                entry.set_text("")
                continue

            entry.set_text(f(input_text, hmac))

    def _convertText(self, text, text_type):
        if text_type == "Base64":
            return base64.b64decode(text)
        elif text_type == "Hex":
            return text.decode("hex")
        else:
            Exception("This should not happen")


def main():
    builder = Gtk.Builder()
    builder.add_from_file("./hashtool.glade")
    builder.connect_signals(MainWindowHandler(builder))

    window = builder.get_object("mainwindow")
    window.show_all()

    Gtk.main()


if __name__ == "__main__":
    main()

