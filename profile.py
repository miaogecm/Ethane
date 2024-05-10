#!/usr/bin/python

import geni.portal as portal
import geni.rspec.pg as RSpec

pc = portal.Context()

pc.defineParameter('n', 'Number of nodes', portal.ParameterType.INTEGER, 8)

params = pc.bindParameters()

request = pc.makeRequestRSpec()

link = request.Link('link0')
link.Site('site0')

for node_id in range(params.n):
    node = request.RawPC('node{}'.format(node_id))
    node.routable_control_ip = True
    node.hardware_type = 'r650'
    node.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU18-64-STD'

    node.addService(RSpec.Execute(shell='sh', command='sudo cp ~/.ssh/authorized_keys /root/.ssh/authorized_keys'))
    node.addService(RSpec.Execute(shell='sh', command='sudo cp -r /local/repository /root/DPMFS'))
    node.addService(RSpec.Execute(shell='sh', command='sudo bash -c "cd /root/DPMFS && ./install.sh"'))

    iface = node.addInterface('iface{}'.format(node_id))
    link.addInterface(iface)

pc.printRequestRSpec(request)
