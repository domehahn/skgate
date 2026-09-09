#!/usr/bin/env python3
import argparse, hashlib, json, os
from datetime import datetime, timezone
p=argparse.ArgumentParser();p.add_argument('--artifact',required=True);p.add_argument('--name',required=True);p.add_argument('--version',required=True);p.add_argument('--output',required=True);a=p.parse_args()
with open(a.artifact,'rb') as f: sha=hashlib.sha256(f.read()).hexdigest()
now=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
doc={
  'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT',
  'name':f'{a.name}-{a.version}','documentNamespace':f'https://github.com/domehahn/{a.name}/sbom/{a.version}/{sha}',
  'creationInfo':{'created':now,'creators':['Tool: project-release-sbomgen-1.0']},
  'packages':[{'name':a.name,'SPDXID':'SPDXRef-Package','versionInfo':a.version,'downloadLocation':'NOASSERTION','filesAnalyzed':False,
    'checksums':[{'algorithm':'SHA256','checksumValue':sha}],
    'supplier':'Organization: Open Source Project','licenseConcluded':'MIT','licenseDeclared':'MIT','copyrightText':'NOASSERTION'}],
  'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':'SPDXRef-Package'}]
}
with open(a.output,'w') as f: json.dump(doc,f,indent=2);f.write('\n')
