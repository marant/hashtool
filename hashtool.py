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

import wx
import zlib
from Crypto.Hash import MD2, MD4, MD5, SHA, SHA224, SHA256, SHA384, SHA512, RIPEMD, HMAC
import tiger
import binascii
import base64

INPUT_TYPES = ["ASCII", "Base64", "Hex"]
WINDOW_SIZE = (500,700)

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
        #self.hashfuncs["tiger"] = self._hashTiger

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

    def _hashTiger(self, value, hmacKey):
        return self._cryptolibwrapper(tiger, value, hmacKey)

    def _cryptolibwrapper(self, alg, value, hmacKey=None):
        if hmacKey == None:
            return alg.new(value).hexdigest()

        h = HMAC.new(str(hmacKey), digestmod=alg)
        h.update(value)
        return h.hexdigest()


class HashTool(wx.Frame):
    def __init__(self, *args, **kwargs):
        super(HashTool, self).__init__(*args, **kwargs)
        self.hash_fields = {}
        self.hash_funcs = {}
        self.salt = None
        self.menubar = None
        self.panel = None
        self.input_format = None
        self.hmac_enabled = False
        self.hmac_key = None

        self.InitUI()
        self.Show(True)

    def InitUI(self):
        self.SetSize(WINDOW_SIZE)
        self.SetTitle("HashTool")

        self.panel = wx.Panel(self)
        self.vbox = wx.BoxSizer(wx.VERTICAL)

        self._createMenuBar()
        self._createInputLabels()
        self._createInputField()
        self._createHMACLabels()
        self._createHMACField()
        self._createLine()
        self._createHashFields()
        self._createLine()
        self._createCalculateButton()

        self.panel.SetSizer(self.vbox)

    def _createMenuBar(self):
        self.menubar = wx.MenuBar()
        fileMenu = wx.Menu()
        fitem = fileMenu.Append(wx.ID_EXIT, "Quit", "Quit Application")
        self.menubar.Append(fileMenu, "&File")
        self.SetMenuBar(self.menubar)

        self.Bind(wx.EVT_MENU, self.OnQuit, fitem)

    def _inputFormatChanged(self, e):
        self.input_format = e.GetString()

    def _createLine(self):
        line = wx.StaticLine(self.panel)
        self.vbox.Add(line, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

    def _createHMACLabels(self):
        label_hbox = wx.BoxSizer(wx.HORIZONTAL)
        key_format_label = wx.StaticText(self.panel, label="Key Format")
        key_label = wx.StaticText(self.panel, label="Key")
        label_hbox.AddStretchSpacer(1)
        label_hbox.Add(key_format_label, proportion=1)
        label_hbox.Add(key_label, proportion=3)
        self.vbox.Add(label_hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

    def _createHMACField(self):
        hbox = wx.BoxSizer(wx.HORIZONTAL)

        hmac_checkbox = wx.CheckBox(self.panel, label="HMAC", style=wx.ALIGN_RIGHT)
        hmac_checkbox.SetValue(False)
        hmac_checkbox.Bind(wx.EVT_CHECKBOX, self._toggleHMAC)

        self.hmac_combobox = wx.ComboBox(self.panel, choices=INPUT_TYPES, style=wx.CB_READONLY|wx.CB_DROPDOWN)
        self.hmac_combobox.SetValue(INPUT_TYPES[0])
        self.hmac_format = INPUT_TYPES[0] # set chosen input format to default
        self.hmac_combobox.Bind(wx.EVT_COMBOBOX, self._hmacFormatChanged)

        self.hmac_key_field = wx.TextCtrl(self.panel, style=wx.TE_PROCESS_ENTER)
        self.hmac_key_field.Disable()
        self.hmac_combobox.Disable()

        hbox.Add(hmac_checkbox, proportion=1)
        hbox.Add(self.hmac_combobox, proportion=1)
        hbox.Add(self.hmac_key_field, proportion=3)

        self.Bind(wx.EVT_TEXT, self._hmacKeyChanged, id=self.hmac_key_field.GetId())
        self.Bind(wx.EVT_TEXT_ENTER, self._calculateHashes, id=self.hmac_key_field.GetId())

        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT, border=10)

    def _toggleHMAC(self, e):
        self.hmac_enabled = e.GetEventObject().GetValue()
        if self.hmac_enabled:
            self.hmac_combobox.Enable()
            self.hmac_key_field.Enable()
        else:
            self.hmac_combobox.Disable()
            self.hmac_key_field.Disable()
            self.hmac_key_field.Clear()
            self.hmac_key = None

    def _hmacFormatChanged(self, e):
        self.hmac_format = e.GetString()

    def _hmacKeyChanged(self, e):
        self.hmac_key = self.hmac_key_field.Value

    def _createInputLabels(self):
        label_hbox = wx.BoxSizer(wx.HORIZONTAL)
        key_format_label = wx.StaticText(self.panel, label="Data Format")
        key_label = wx.StaticText(self.panel, label="Data")
        label_hbox.AddStretchSpacer(1)
        label_hbox.Add(key_format_label, proportion=1)
        label_hbox.Add(key_label, proportion=3)
        self.vbox.Add(label_hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

    def _createInputField(self):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.input_field = wx.TextCtrl(self.panel, style=wx.TE_PROCESS_ENTER)

        self.Bind(wx.EVT_TEXT_ENTER, self._calculateHashes, id=self.input_field.GetId())

        cbox = wx.ComboBox(self.panel, choices=INPUT_TYPES, style=wx.CB_READONLY|wx.CB_DROPDOWN)
        cbox.SetValue(INPUT_TYPES[0])
        self.input_format = INPUT_TYPES[0] # set chosen input format to default
        cbox.Bind(wx.EVT_COMBOBOX, self._inputFormatChanged)

        hbox.AddStretchSpacer(1)
        hbox.Add(cbox, flag=wx.LEFT, proportion=1)
        hbox.Add(self.input_field, proportion=3)
        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT, border=10)

    def _createHashFields(self):
        hasher = Hasher()
        self._addHashValue("MD2", lambda value, hmacKey = None: hasher.Hash("md2", value, hmacKey))
        self._addHashValue("MD4", lambda value, hmacKey = None: hasher.Hash("md4", value, hmacKey))
        self._addHashValue("MD5", lambda value, hmacKey = None: hasher.Hash("md5", value, hmacKey))
        self._addHashValue("SHA-1", lambda value, hmacKey = None: hasher.Hash("sha", value, hmacKey))
        self._addHashValue("SHA-224", lambda value, hmacKey = None: hasher.Hash("sha224", value, hmacKey))
        self._addHashValue("SHA-256", lambda value, hmacKey = None: hasher.Hash("sha256", value, hmacKey))
        self._addHashValue("SHA-384", lambda value, hmacKey = None: hasher.Hash("sha384", value, hmacKey))
        self._addHashValue("SHA-512", lambda value, hmacKey = None: hasher.Hash("sha512", value, hmacKey))
        self._addHashValue("RIPEMD", lambda value, hmacKey = None: hasher.Hash("ripemd", value, hmacKey))

	# TODO: Make these work with HMAC
        #self._addHashValue("tiger", lambda value, hmacKey = None: hasher.Hash("tiger", value, hmacKey))
        #self._addHashValue("adler32", self._adler32())
        #self._addHashValue("CRC32", self._zlib_wrapper(zlib.crc32))

    def _addHashValue(self, hashName, hashFunc):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.panel, label=hashName)
        hbox.Add(label, flag=wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, proportion=1)
        textField = wx.TextCtrl(self.panel)
        textField.SetEditable(False)
        hbox.Add(textField, proportion=4)
        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)
        self.hash_fields[hashName] = (textField, hashFunc)

    def _createCalculateButton(self):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        calc_button = wx.Button(self.panel, wx.ID_ANY, 'Calculate', (10, 10))
        self.Bind(wx.EVT_BUTTON, self._calculateHashes, id=calc_button.GetId())
        hbox.AddStretchSpacer(4)
        hbox.Add(calc_button, proportion=2)
        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

    def _zlib_wrapper(self, f):
        return lambda secret: str(f(secret))

    def _adler32(self):
        return lambda secret: hex(zlib.adler32(secret))

    def OnQuit(self, e):
        self.Close()

    def _calculateHashes(self, e):
        pwd = self.input_field.Value
        key = self.hmac_key_field.Value
        try:
            # check input format
            if self.input_format == INPUT_TYPES[0]: # ASCII
                pass
            elif self.input_format == INPUT_TYPES[1]: # Base64
                pwd = base64.b64decode(pwd)
            elif self.input_format == INPUT_TYPES[2]: # Hex
                pwd = pwd.decode("hex")

            # check key format
            if self.hmac_format == INPUT_TYPES[0]: # ASCII
                pass
            elif self.hmac_format == INPUT_TYPES[1]: # Bas64
                key = base64.b64decode(key)
            elif self.hmac_format == INPUT_TYPES[2]: # Hex
                key = key.decode("hex")

        except TypeError:
            wx.MessageBox("Bad input", "Error", wx.OK|wx.ICON_WARNING)
            return

        for hashKey, hashTuple in self.hash_fields.iteritems():
            hashField = hashTuple[0]
            hashFunc = hashTuple[1]

            hashed = None
            if key == None:
                hashed = hashFunc(pwd)
            else:
                hashed = hashFunc(pwd, key)

            if hashed != None:
                hashField.SetValue(hashed)

def main():
    ex = wx.App()
    HashTool(None)
    ex.MainLoop()

if __name__ == "__main__":
    main()

