#!/usr/bin/env python3
"""Offline builder for the separate GPL converter; never runs a proxy core."""
import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
WRAPPER=ROOT/"third_party/mihomo-importer"
PIN=json.loads((ROOT/"internal/managedproxy/manifest.json").read_text())
MANIFEST=ROOT/"internal/managedproxy/importer_manifest.json"
PLATFORMS={"darwin/arm64":"mihomo-importer","windows/amd64":"MihomoImporter.exe"}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def checked_archive(path,digest,destination,prefix):
    if sha(path)!=digest:
        raise ValueError("Pinned importer source/vendor checksum mismatch")
    with tarfile.open(path,"r:gz") as archive:
        for member in archive.getmembers():
            relative=pathlib.PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe importer source archive")
            if prefix and (not relative.parts or relative.parts[0]!=prefix):
                raise ValueError("Unexpected importer source prefix")
        archive.extractall(destination)

def source_archive():
    names=("main.go","main_test.go","go.mod","README.md","LICENSE")
    buf=io.BytesIO()
    with gzip.GzipFile(fileobj=buf,mode="wb",mtime=0,filename="") as zipped:
        with tarfile.open(fileobj=zipped,mode="w") as tar:
            for name in names:
                data=(WRAPPER/name).read_bytes();info=tarfile.TarInfo("mihomo-importer/"+name)
                info.size=len(data);info.mode=0o644;info.mtime=0
                tar.addfile(info,io.BytesIO(data))
            data=pathlib.Path(__file__).read_bytes();info=tarfile.TarInfo("mihomo-importer/build-native-importer.py")
            info.size=len(data);info.mode=0o755;info.mtime=0;tar.addfile(info,io.BytesIO(data))
    return buf.getvalue()

def main():
    p=argparse.ArgumentParser();p.add_argument("platform",choices=(*PLATFORMS,"all"));p.add_argument("output",type=pathlib.Path)
    p.add_argument("--test",action="store_true");p.add_argument("--race",action="store_true");p.add_argument("--update-manifest",action="store_true");a=p.parse_args()
    if a.race and not a.test:raise ValueError("--race requires --test")
    go=pathlib.Path(os.environ.get("EXITGUARD_GO",str(pathlib.Path.home()/"go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go")))
    env=dict(os.environ);env.update({"GOTOOLCHAIN":"local","GOFLAGS":"","GOWORK":"off","CGO_ENABLED":"0","GOCACHE":str(ROOT/".work/go-cache")})
    if not subprocess.check_output([str(go),"version"],env=env,text=True).startswith("go version go1.27.3 "):
        raise ValueError("Pinned Go 1.27.3 required")
    work=ROOT/".work";work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mihomo-importer-build-",dir=work) as temp:
        temp=pathlib.Path(temp)
        checked_archive(work/"managed-core/mihomo-source.tar.gz",PIN["source_sha256"],temp,"mihomo-1.19.33")
        source=temp/"mihomo-1.19.33"
        checked_archive(work/"managed-core/mihomo-vendor.tar.gz",PIN["vendor_sha256"],source,"vendor")
        command=source/"cmd/exitguard-native-importer";command.mkdir(parents=True)
        for name in ("main.go","main_test.go"):
            if (WRAPPER/name).exists():shutil.copyfile(WRAPPER/name,command/name)
        dependencies=subprocess.check_output([str(go),"list","-mod=vendor","-deps","./cmd/exitguard-native-importer"],cwd=source,env=env,text=True).splitlines()
        forbidden=("github.com/metacubex/mihomo/adapter","github.com/metacubex/mihomo/config","github.com/metacubex/mihomo/provider","github.com/metacubex/mihomo/hub","github.com/metacubex/mihomo/listener","github.com/metacubex/mihomo/tunnel")
        if any(dep==prefix or dep.startswith(prefix+"/") for dep in dependencies for prefix in forbidden):
            raise ValueError("Native importer must not link adapter/config/provider/listener packages")
        if a.test:
            if a.race:env["CGO_ENABLED"]="1"
            subprocess.run([str(go),"test","-mod=vendor",*(["-race"] if a.race else []),"./cmd/exitguard-native-importer","-count=1"],cwd=source,env=env,check=True)
            return
        assets={};platforms=PLATFORMS if a.platform=="all" else [a.platform]
        for platform in platforms:
            target=a.output.resolve()/platform.replace("/","-");target.mkdir(parents=True,exist_ok=True)
            binary=target/PLATFORMS[platform];buildenv=dict(env);buildenv.update(zip(("GOOS","GOARCH"),platform.split("/")))
            flags="-s -w"+(" -H=windowsgui" if platform.startswith("windows/") else "")
            subprocess.run([str(go),"build","-mod=vendor","-trimpath","-buildvcs=false","-ldflags",flags,"-o",str(binary),"./cmd/exitguard-native-importer"],cwd=source,env=buildenv,check=True)
            if platform.startswith("darwin/"):
                subprocess.run(["codesign","--force","--sign","-",str(binary)],check=True)
                subprocess.run(["codesign","--verify","--strict",str(binary)],check=True)
            assets[platform]={"binary":binary.name,"sha256":sha(binary)}
        archive=source_archive();archive_hash=hashlib.sha256(archive).hexdigest()
        a.output.resolve().mkdir(parents=True,exist_ok=True)
        (a.output.resolve()/"mihomo-importer-source.tar.gz").write_bytes(archive)
        metadata={"protocol_version":1,"core_version":PIN["version"],"source_commit":PIN["source_commit"],"source_sha256":PIN["source_sha256"],"vendor_sha256":PIN["vendor_sha256"],"wrapper_source_sha256":archive_hash,"assets":assets}
        if a.update_manifest:
            if a.platform!="all":raise ValueError("Update both importer platforms together")
            temporary=MANIFEST.with_suffix(".json.tmp");temporary.write_text(json.dumps(metadata,indent=2)+"\n");temporary.replace(MANIFEST)
        else:
            expected=json.loads(MANIFEST.read_text())
            for key in metadata:
                if key=="assets":
                    for platform,asset in assets.items():
                        if expected[key].get(platform)!=asset:raise ValueError("Importer binary differs from pinned generated manifest")
                elif expected[key]!=metadata[key]:raise ValueError("Importer source differs from generated manifest; update it explicitly before release")
        print("Verified separate native importer: "+", ".join(assets))

if __name__=="__main__":
    try:main()
    except (OSError,ValueError,subprocess.CalledProcessError) as exc:
        print("Native importer build failed: "+str(exc),file=sys.stderr);sys.exit(1)
