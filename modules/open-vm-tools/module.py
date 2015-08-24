import os
from osv.modules import api
from osv.modules.filemap import FileMap

_base = '${OSV_BASE}/modules/open-vm-tools/install'

usr_files = FileMap()
usr_files.add(os.path.join(_base, 'usr/lib/libvmtools.so')) \
         .to('/usr/lib/libvmtools.so.0')

api.require('libglib')
