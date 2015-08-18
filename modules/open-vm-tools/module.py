import os
from osv.modules import api
from osv.modules.filemap import FileMap

_base = '${OSV_BASE}/modules/open-vm-tools/install'

usr_files = FileMap()
usr_files.add(os.path.join(_base, 'usr/lib/libvmtools.so')) \
         .to('/usr/lib/libvmtools.so.0')
usr_files.add(os.path.join(_base, 'usr/bin/vmtoolsd.so')) \
         .to('vmtoolsd.so')
usr_files.add(os.path.join(_base, 'usr/lib/open-vm-tools/plugins/vmsvc/libguestInfo.so')) \
         .to('/usr/lib/open-vm-tools/plugins/vmsvc/libguestInfo.so')

api.require('libglib')

daemon = api.run_on_init('/vmtoolsd.so &!')
default = daemon
