#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

/// Synthetic credentials travel only through anonymous pipes/PTY; audit stores
/// length and FNV-1a for test comparisons, never the credential itself.
final class S03PINFidelityTests: XCTestCase {
    struct Fixture {
        let root: URL, module: URL, signer: SoftwareSigner
        init() throws {
            root = try FixtureFiles.directory("s03-input")
            signer = try SoftwareSigner(folder: root)
            module = root.appendingPathComponent("mock.dylib")
            let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let header = root.appendingPathComponent("key.h")
            let cert = signer.der.map(String.init).joined(separator: ",")
            let key = try signer.rsaPrivateDER().map(String.init).joined(separator: ",")
            try Data(("#define SIGNUM_MOCK_BOOTSTRAP_CERTIFICATE 1\nstatic const unsigned char bootstrap_certificate[]={"+cert+"};\n#define SIGNUM_MOCK_SOFTWARE_KEY 1\nstatic const unsigned char bootstrap_private_key[]={"+key+"};\n").utf8).write(to: header)
            let source = root.appendingPathComponent("mock.c")
            let code = """
            #include <stdio.h>
            #include <stdint.h>
            #define C_GetFunctionList s03_original_function_list
            #include "mock_provider.c"
            #undef C_GetFunctionList
            static CK_RV observed_login(CK_SESSION_HANDLE session, CK_USER_TYPE type, CK_UTF8CHAR_PTR pin, CK_ULONG length) {
                uint64_t hash=UINT64_C(14695981039346656037);
                for(CK_ULONG i=0;i<length;i++){ hash^=pin[i]; hash*=UINT64_C(1099511628211); }
                FILE *f=fopen("\(root.appendingPathComponent("login-metadata").path)","a");
                if(f){fprintf(f,"%lu %llu\\n",(unsigned long)length,(unsigned long long)hash);fclose(f);}
                return login(session,type,pin,length);
            }
            CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out){functions.C_Login=observed_login;*out=&functions;return CKR_OK;}
            """
            try Data(code.utf8).write(to: source)
            let p=Process();p.executableURL=URL(fileURLWithPath:"/usr/bin/cc")
            p.arguments=["-dynamiclib","-pthread","-I",repo.appendingPathComponent("Tools/PKCS11Tests").path,"-I",repo.appendingPathComponent("Sources/CPKCS11").path,"-include",header.path,"-DSIGNUM_MOCK_AUDIT_PATH="+String(reflecting:root.appendingPathComponent("operations").path),source.path,"-framework","Security","-framework","CoreFoundation","-o",module.path]
            p.standardOutput=FileHandle.nullDevice;try p.run();try FixtureProcess.wait(p)
            guard p.terminationStatus==0 else {throw SignumError.module("Synthetic mock build failed")}
        }
        func reset() throws {
            for name in ["operations","login-metadata"] {try Data().write(to:root.appendingPathComponent(name))}
        }
        func operations() -> [String] {((try? String(contentsOf:root.appendingPathComponent("operations"))) ?? "").split(separator:"\n").map(String.init)}
        func logins() -> [[UInt64]] {((try? String(contentsOf:root.appendingPathComponent("login-metadata"))) ?? "").split(separator:"\n").map{$0.split(separator:" ").compactMap{UInt64($0)}}}
    }
    private var bin: URL {Bundle(for:Self.self).bundleURL.deletingLastPathComponent()}
    private func hash(_ bytes: Data) -> UInt64 {bytes.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211}}
    private let inputs: [Data] = [Data(),Data([65]),Data("S03-SYNTHETIC-only".utf8),Data(repeating:81,count:64),Data(repeating:81,count:65),Data("S03\rTAIL".utf8),Data("S03\nTAIL".utf8),Data("S03\r\nTAIL".utf8),Data("S03\0TAIL".utf8),Data("  S03-spaces  ".utf8),Data("é漢字".utf8),Data([83,48,51,0xff,0x80,65])]
    private func permittedTerminal(_ data: Data) -> Bool { (1...64).contains(data.count) && !data.contains(where:{[0,10,13].contains($0)}) && String(data:data,encoding:.utf8) != nil }
    private func assertAudit(_ f: Fixture, input: Data, valid: Bool, sessionsMustBeAbsent: Bool = true, file: StaticString = #filePath, line: UInt = #line) {
        let received=f.logins(), ops=f.operations()
        if valid {
            XCTAssertEqual(received.count,1,file:file,line:line)
            XCTAssertEqual(received.first,[UInt64(input.count),hash(input)],"Byte equality at mock C_Login",file:file,line:line)
        } else {
            XCTAssertTrue(received.isEmpty,"Rejected input reached Login",file:file,line:line)
            XCTAssertFalse(ops.contains("8"));XCTAssertFalse(ops.contains("16"))
            if sessionsMustBeAbsent {XCTAssertFalse(ops.contains("5"),"Rejected input opened a PKCS#11 session",file:file,line:line)}
        }
    }
    private func terminal(_ args: [String], input: Data, root: URL) throws -> [String:Any] {
        let script=root.appendingPathComponent("pty.py")
        try Data(#"""
        import os,sys,json,base64,time,select,termios,signal
        config=json.load(sys.stdin);payload=base64.b64decode(config['input'])
        pid,fd=os.forkpty()
        if pid==0: os.execv(config['args'][0],config['args'])
        initial=termios.tcgetattr(fd);output=b'';sent=False;protected=False;status=None
        deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([fd],[],[],0.02)
                if ready:
                    try: chunk=os.read(fd,8192)
                    except OSError: chunk=b''
                    output+=chunk
                    if not sent and b'Token PIN' in output and output.endswith(b': '):
                        protected=not bool(termios.tcgetattr(fd)[3]&termios.ECHO)
                        os.write(fd,payload+b'\n');sent=True
                done,value=os.waitpid(pid,os.WNOHANG)
                if done: status=value;break
            if status is None:
                os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
            restored=termios.tcgetattr(fd)==initial
            print(json.dumps({'sent':sent,'protected':protected,'restored':restored,'clean':len(payload)<8 or payload not in output,'failed':os.waitstatus_to_exitcode(status)!=0,'reason':next((line for line in output.decode('utf-8','replace').splitlines() if line.startswith('Signum error:')),'').replace(payload.decode('utf-8','replace') or 'unused','[redacted]'),'pinError':b'PIN' in output and (b'rifiut' in output or b'represent' in output or b'Invalid' in output)}))
        finally: os.close(fd)
        """#.utf8).write(to:script)
        let p=Process();p.executableURL=URL(fileURLWithPath:"/usr/bin/python3");p.arguments=[script.path]
        let stdin=Pipe(),stdout=Pipe();p.standardInput=stdin;p.standardOutput=stdout;p.standardError=FileHandle.nullDevice
        try p.run()
        let request=try JSONSerialization.data(withJSONObject:["args":args,"input":input.base64EncodedString()])
        try stdin.fileHandleForWriting.write(contentsOf:request);try stdin.fileHandleForWriting.close()
        try FixtureProcess.wait(p,timeout:20)
        return try XCTUnwrap(JSONSerialization.jsonObject(with:stdout.fileHandleForReading.readDataToEndOfFile()) as? [String:Any])
    }
    func testCLITerminalRejectsWholeUnrepresentableInputBeforeAnySessionAndPreservesValidBytes() throws {
        let f=try Fixture();defer{try? FileManager.default.removeItem(at:f.root)}
        for (index,input) in inputs.enumerated() {
            try f.reset();let allowed=permittedTerminal(input)
            let r=try terminal([(ProcessInfo.processInfo.environment["SIGNUM_TEST_CLI"] ?? bin.appendingPathComponent("SignumCLI").path),"sign-test","7","53",f.module.path],input:input,root:f.root)
            XCTAssertEqual(r["sent"] as? Bool,true,"case \(index)")
            XCTAssertEqual(r["protected"] as? Bool,true);XCTAssertEqual(r["restored"] as? Bool,true)
            XCTAssertEqual(r["clean"] as? Bool,true,"No PIN in diagnostic/TTY output")
            if !allowed {XCTAssertEqual(r["pinError"] as? Bool,true,"Clear PIN rejection, case \(index)")}
            if allowed { XCTAssertEqual(r["failed"] as? Bool, false, String(describing:r["reason"])) }
            assertAudit(f,input:input,valid:allowed)
        }
    }
    func testPAdESTerminalHasSameByteFaithfulOrRejectContract() throws {
        let f=try Fixture();defer{try? FileManager.default.removeItem(at:f.root)}
        let source=f.root.appendingPathComponent("source.pdf"),bytes=try PAdESAppearanceTests().pdf();try bytes.write(to:source)
        let helper=try FixtureRequirements.helper()
        for (index,input) in inputs.enumerated() {
            try f.reset()
            let args=[helper,source.path,f.root.appendingPathComponent("out-\(index).pdf").path,f.module.path,"7","01","--job-id",UUID().uuidString,"--snapshot-id",UUID().uuidString,"--expected-document-sha256",DocumentSnapshot.digest(bytes),"--expected-cert-sha256",DocumentSnapshot.digest(f.signer.der),"--verified-output-v3"]
            let r=try terminal(args,input:input,root:f.root)
            XCTAssertEqual(r["sent"] as? Bool,true);XCTAssertEqual(r["protected"] as? Bool,true)
            XCTAssertEqual(r["restored"] as? Bool,true);XCTAssertEqual(r["clean"] as? Bool,true)
            assertAudit(f,input:input,valid:permittedTerminal(input))
        }
    }
    func testOneShotWorkerPreservesControlBytesInItsLengthDelimitedDomainOrRejectsBeforeSession() throws {
        let f=try Fixture();defer{try? FileManager.default.removeItem(at:f.root)}
        let client=IsolatedPKCS11Client(executable:bin.appendingPathComponent("SignumPKCS11Worker"))
        for input in inputs {
            try f.reset();guard let value=String(data:input,encoding:.utf8) else {continue}
            let valid=(1...64).contains(input.count) && !input.contains(0)
            _ = try? client.sign(provider:f.module.path,slot:7,certificate:.init(label:"Synthetic",identifier:Data([1])),der:f.signer.der,attributes:Data([0x31,0]),pin:value,id:UUID())
            assertAudit(f,input:input,valid:valid)
        }
    }
    func testBatchAndTemporaryReuseKeepExactAcceptedPINBytes() throws {
        let f=try Fixture();defer{try? FileManager.default.removeItem(at:f.root)}
        let inspected=try MiddlewareFileSecurity.inspect(f.module.path,automatic:false)
        for temporary in [false,true] {
            for input in inputs {
                try f.reset();guard let value=String(data:input,encoding:.utf8) else {continue}
                let valid=(1...64).contains(input.count) && !input.contains(0)
                let jobs=try (0..<2).map{_ in BatchWorkerJob(id:UUID(),snapshotID:UUID(),sha256:String(repeating:"a",count:64),attributes:try CAdES.Prepared(document:Data("synthetic".utf8),certificateDER:f.signer.der).attributesToSign)}
                var m=BatchWorkerStart(version:temporary ? 3:2,batchID:UUID(),provider:inspected.canonicalPath,slot:7,serial:"SYNTHETIC-0001",certificate:.init(.init(label:"Synthetic",identifier:Data([1])),der:f.signer.der),automatic:false,moduleIdentity:inspected.identity,jobs:jobs,pin:nil)
                if temporary {m.temporaryPIN=true}
                let c=BatchSignatureConnection(manifest:m,executable:bin.appendingPathComponent("SignumPKCS11Worker"))
                do {
                    _ = try c.sign(jobID:jobs[0].id,attributes:jobs[0].attributes,pin:value)
                    _ = try c.sign(jobID:jobs[1].id,attributes:jobs[1].attributes,pin:nil)
                    try c.finish()
                } catch {c.abort();if valid {XCTFail("Valid synthetic batch input rejected")}}
                assertAudit(f,input:input,valid:valid)
            }
        }
    }
}
#endif
