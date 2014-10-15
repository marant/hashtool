#!/usr/bin/python

import wx
import hashlib
import zlib
from Crypto.Hash import MD2, MD4, RIPEMD
import tiger
import binascii
import base64

INPUT_TYPES = ["ASCII", "Base64", "Hex"]
WINDOW_SIZE = (500,700)

class HashCalc(wx.Frame):
    def __init__(self, *args, **kwargs):
        super(HashCalc, self).__init__(*args, **kwargs)
        self.hash_fields = {}
        self.hash_funcs = {}
        self.salt = None
        self.menubar = None
        self.panel = None
        self.input_format = None
        self.hmac_enabled = False

        self.InitUI()
        self.Show(True)

    def InitUI(self):
        self.SetSize(WINDOW_SIZE)
        self.SetTitle("HashCalc")

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

        self.Bind(wx.EVT_TEXT_ENTER, self._hmacKeyChanged, id=self.hmac_key_field.GetId())

        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT, border=10)

    def _toggleHMAC(self, e):
        self.hmac_enabled = e.GetEventObject().GetValue()
        if self.hmac_enabled:
            self.hmac_combobox.Enable()
            self.hmac_key_field.Enable()
        else:
            self.hmac_combobox.Disable()
            self.hmac_key_field.Disable()

    def _hmacFormatChanged(self, e):
        self.hmac_format = e.GetString()
    def _hmacKeyChanged(self, e):
        pass

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
        self._addHashValue("MD2", self._md2())
        self._addHashValue("MD4", self._md4())
        self._addHashValue("MD5", self._hashlib_wrapper(hashlib.md5))
        self._addHashValue("SHA1", self._hashlib_wrapper(hashlib.sha1))
        self._addHashValue("SHA224", self._hashlib_wrapper(hashlib.sha224))
        self._addHashValue("SHA256", self._hashlib_wrapper(hashlib.sha256))
        self._addHashValue("SHA384", self._hashlib_wrapper(hashlib.sha384))
        self._addHashValue("SHA512", self._hashlib_wrapper(hashlib.sha512))
        self._addHashValue("RIPEMD", self._ripemd())
        self._addHashValue("tiger", self._tiger())
        self._addHashValue("adler32", self._adler32())
        self._addHashValue("CRC32", self._zlib_wrapper(zlib.crc32))

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

    def _hashlib_wrapper(self, f):
        return lambda secret: f(secret).hexdigest()

    def _zlib_wrapper(self, f):
        return lambda secret: str(f(secret))

    def _adler32(self):
        return lambda secret: hex(zlib.adler32(secret))

    def _md2(self):
        return lambda secret: MD2.new(secret).hexdigest()

    def _ripemd(self):
        return lambda secret: RIPEMD.new(secret).hexdigest()

    def _md4(self):
        return lambda secret: MD4.new(secret).hexdigest()

    def _tiger(self):
        return lambda secret: tiger.new(secret).hexdigest()

    def OnQuit(self, e):
        self.Close()

    def _calculateHashes(self, e):
        pwd = self.input_field.Value
        try:
            if self.input_format == INPUT_TYPES[0]: # ASCII
                pass
            elif self.input_format == INPUT_TYPES[1]: # Base64
                    pwd = base64.b64decode(pwd)
            elif self.input_format == INPUT_TYPES[2]: # Hex
                pwd = pwd.decode("hex")
        except TypeError:
            wx.MessageBox("Bad input", "Error", wx.OK|wx.ICON_WARNING)
            return

        for hashKey, hashTuple in self.hash_fields.iteritems():
            hashField = hashTuple[0]
            hashFunc = hashTuple[1]
            hashed = hashFunc(pwd)

            if hashed != None:
                hashField.SetValue(hashed)

def main():
    ex = wx.App()
    HashCalc(None)
    ex.MainLoop()

if __name__ == "__main__":
    main()

