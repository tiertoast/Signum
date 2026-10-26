#!/usr/bin/env python3
"""Build 12B native contracts: static synthetic backend only; no installed middleware."""
import argparse, os, pathlib, subprocess, sys, tempfile
root=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--configuration',choices=['debug','release'],default='debug');a=p.parse_args()
if sys.platform!='darwin':raise SystemExit('Native journal durability requires macOS; no portable success substitute.')
with tempfile.TemporaryDirectory(prefix='signum-pin12b-') as raw:
 stage=pathlib.Path(raw).resolve();opt=['-O0','-g'] if a.configuration=='debug' else ['-O2']
 includes=['-I'+str(root/x) for x in ['Sources/CPINManagement/include','Sources/CSecurePIN/include','Sources/COutputPermissions/include','Sources/CProcessCoordination/include','Sources/CPKCS11','Tools/PKCS11Tests']]
 common=['/usr/bin/cc','-std=c11','-D_DEFAULT_SOURCE','-DSIGNUM_PIN_ADMIN_TESTING','-DSIGNUM_MOCK_PIN_ADMIN','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-pthread',*opt,*includes]
 sources=['Tools/PINManagementTests/qualification_tests.c','Sources/CPINManagement/pin_management.c','Sources/CPINManagement/pin_journal.c','Sources/CSecurePIN/secure_pin.c','Sources/COutputPermissions/output_permissions.c','Sources/COutputPermissions/discovery_permissions.c','Sources/CProcessCoordination/process_coordination.c','Tools/PKCS11Tests/mock_provider.c']
 subprocess.run([*common,'-include',str(root/'Tools/PINManagementTests/portable_mock.h'),*[str(root/x) for x in sources],'-o',str(stage/'contracts')],check=True)
 env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':os.environ['HOME'],'LC_ALL':'C'}
 for case in range(34):
  folder=stage/str(case);folder.mkdir(mode=0o700)
  subprocess.run([str(stage/'contracts'),str(folder),str(case)],check=True,timeout=15,env=env)
 for origin,recovery in [(6,34),(0,35)]:
  subprocess.run([str(stage/'contracts'),str(stage/str(origin)),str(recovery)],check=True,timeout=15,env=env)
 folder=stage/'capacity';folder.mkdir(mode=0o700)
 subprocess.run([str(stage/'contracts'),str(folder),'36'],check=True,timeout=60,env=env)
 folder=stage/'named-pipe';folder.mkdir(mode=0o700)
 subprocess.run([str(stage/'contracts'),str(folder),'37'],check=True,timeout=15,env=env)
 for case in [38,39,40]:
  folder=stage/str(case);folder.mkdir(mode=0o700)
  subprocess.run([str(stage/'contracts'),str(folder),str(case)],check=True,timeout=15,env=env)
 for src in ['pin_management','pin_journal']:
  obj=stage/(src+'.o');subprocess.run(['/usr/bin/cc',*opt,*includes,'-c',str(root/'Sources/CPINManagement'/(src+'.c')),'-o',str(obj)],check=True)
  symbols=subprocess.check_output(['/usr/bin/nm',str(obj)],text=True)
  for forbidden in ['sg_pin_test_','sg_pin_journal_test_','C_SetPIN','C_InitPIN','C_InitToken','C_Login','dlopen','dlsym','mock_']:
   if forbidden in symbols:raise SystemExit('Forbidden production symbol: '+forbidden)
 print('PASS production journal/transport: no synthetic backend or real mutation imports')
