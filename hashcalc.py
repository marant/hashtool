#!/usr/bin/python

import wx
import hashlib
import zlib
from Crypto.Hash import MD2, MD4, RIPEMD
import tiger
import binascii


class HashCalc(wx.Frame):
    def __init__(self, *args, **kwargs):
        super(HashCalc, self).__init__(*args, **kwargs)
        self.hash_fields = {}
        self.hash_funcs = {}
        self.salt = None

        self.InitUI()
        self.Show(True)


    def InitUI(self):
        menubar = wx.MenuBar()
        fileMenu = wx.Menu()
        fitem = fileMenu.Append(wx.ID_EXIT, "Quit", "Quit Application")
        menubar.Append(fileMenu, "&File")
        self.SetMenuBar(menubar)

        self.Bind(wx.EVT_MENU, self.OnQuit, fitem)

        self.SetSize((400,600))
        self.SetTitle("HashCalc")

        panel = wx.Panel(self) 
        self.panel = panel

        vbox = wx.BoxSizer(wx.VERTICAL)
        self.vbox = vbox


        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        input_label = wx.StaticText(panel, label="Value to hash")
        hbox1.Add(input_label, flag=wx.RIGHT|wx.ALIGN_CENTER_VERTICAL)
        input_field = wx.TextCtrl(panel)
        hbox1.Add(input_field, proportion=4)
        vbox.Add(hbox1, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)
        self.input_field = input_field
        vbox.Add((-1,10))
        calc_button = wx.Button(panel, wx.ID_ANY, 'Calculate', (10, 10))
        self.Bind(wx.EVT_BUTTON, self._buttonClicked, id=calc_button.GetId())
        hbox1.Add(calc_button)

        line1 = wx.StaticLine(self.panel)
        self.vbox.Add(line1, flag=wx.EXPAND|wx.LEFT|wx.RIGHT, border=10)

        # hash value
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

        line2 = wx.StaticLine(self.panel)
        self.vbox.Add(line2, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)

        panel.SetSizer(self.vbox)

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


    def _addHashValue(self, hashName, hashFunc):
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.panel, label=hashName)
        hbox.Add(label, flag=wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, proportion=1)
        textField = wx.TextCtrl(self.panel)
        textField.SetEditable(False)
        hbox.Add(textField, proportion=4)
        self.vbox.Add(hbox, flag=wx.EXPAND|wx.LEFT|wx.RIGHT|wx.TOP, border=10)
        self.hash_fields[hashName] = (textField, hashFunc)

    def OnQuit(self, e):
        self.Close()

    def _buttonClicked(self, e):
        for hashKey, hashTuple in self.hash_fields.iteritems():
            pwd = self.input_field.Value
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

