:: Run from a developer command prompt

echo Generating type library (TLB):
midl.exe credentialprovider.idl -target NT62 /x64

echo Generating .Net interop DLL:
TlbImp2.exe credentialprovider.tlb /out:CredProvider.Interop.dll /unsafe /preservesig
