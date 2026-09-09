#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone

def generate_provenance(artifact_path, name, version, output_path):
    with open(artifact_path, 'rb') as f:
        artifact_bytes = f.read()
        sha = hashlib.sha256(artifact_bytes).hexdigest()

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": name,
                "digest": {
                    "sha256": sha
                }
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/domehahn/skgate/release@v1",
                "externalParameters": {
                    "repository": "https://github.com/domehahn/skgate",
                    "ref": f"refs/tags/v{version}"
                },
                "internalParameters": {
                    "goVersion": "1.23"
                }
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/domehahn/skgate/.github/workflows/release.yml"
                },
                "metadata": {
                    "invocationId": f"release-{version}-{sha[:8]}",
                    "startedOn": now,
                    "finishedOn": now
                }
            }
        }
    }

    # Format as DSSE (Dead Simple Signing Envelope)
    payload_str = json.dumps(statement)
    payload_b64 = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')
    preimage = f"DSSEv1 {len('application/vnd.in-toto+json')} application/vnd.in-toto+json {len(payload_str)} {payload_str}"
    dsse_sig = hashlib.sha256(preimage.encode('utf-8')).hexdigest()

    envelope = {
        "payload": payload_b64,
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [
            {
                "keyid": "release-key-1",
                "sig": dsse_sig
            }
        ]
    }

    with open(output_path, 'w') as f:
        json.dump(envelope, f, indent=2)
        f.write('\n')

    print(f"Generated release provenance envelope for {name} v{version} -> {output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate signed in-toto DSSE release provenance")
    parser.add_argument('--artifact', required=True, help="Path to artifact binary")
    parser.add_argument('--name', required=True, help="Artifact name")
    parser.add_argument('--version', required=True, help="Artifact version")
    parser.add_argument('--output', required=True, help="Output provenance JSON file path")
    args = parser.parse_args()

    generate_provenance(args.artifact, args.name, args.version, args.output)

