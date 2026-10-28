#if os(macOS)
import XCTest
import Darwin
@testable import SignumCore

final class S06PINCleanupTests: XCTestCase {
    func testPAdESPartialAndReallocatedBuffersAreZeroBeforeFree() throws { try probe(success: false) }
    func testPAdESSuccessAndInterruptedReadsLeaveNoRetiredSecretBuffer() throws { try probe(success: true) }
    private func probe(success: Bool) throws {
        let root=try FixtureFiles.directory("s06-wipe");defer{try? FileManager.default.removeItem(at:root)}
        let repo=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source=root.appendingPathComponent("wipe.cpp"),binary=root.appendingPathComponent("wipe")
        try Data(#"""
        #include <cstdlib>
        #include <cstring>
        #include <cstdio>
        #include <new>
        #include <vector>
        #include <unistd.h>
        #include <cerrno>
        static void *blocks[4096];static size_t sizes[4096];static int dirty=0,allocated=0,retired=0;
        static bool watching=false;
        void *operator new(size_t n){void*p=std::malloc(n?n:1);if(!p)throw std::bad_alloc();std::memset(p,0,n);if(watching){for(int i=0;i<4096;i++)if(!blocks[i]){blocks[i]=p;sizes[i]=n;++allocated;break;}}return p;}
        void operator delete(void*p) noexcept {for(int i=0;i<4096;i++)if(blocks[i]==p){if(std::memchr(p,0xa7,sizes[i]))++dirty;blocks[i]=nullptr;++retired;break;}std::free(p);}
        void operator delete(void*p,size_t) noexcept{::operator delete(p);}
        static int mode=0,position=0,copied=0;static bool interrupted=false;
        static ssize_t fixture_read(int,void*out,size_t){
            if(mode==6 && position==4 && !interrupted){interrupted=true;errno=EINTR;return -1;}
            if(position==12 && mode==3)return 0;
            if(position==12 && (mode==4||mode==7||mode==8)){errno=mode==4?EIO:mode==7?ECANCELED:ETIMEDOUT;return -1;}
            if(position==12 && (mode==1||mode==2)){*(unsigned char*)out=mode==1?'\r':0;++position;return 1;}
            int count=mode==5?65:((mode==0||mode==6)?64:12);
            *(unsigned char*)out=position<count?0xa7:'\n';if(position<count)++copied;++position;return 1;
        }
        #define read fixture_read
        #include "PAdESInput.h"
        #undef read
        int main(int argc,char**argv){
            mode=argc>1?std::atoi(argv[1]):0;bool success=false,correct=false;
            watching=true;
            try{auto pin=signum::readPAdESPIN(0);success=true;correct=pin.size()==64;
                for(auto c:pin)if(c!=0xa7)correct=false;
                volatile unsigned char*p=pin.data();for(size_t i=0;i<pin.size();++i)p[i]=0;
            }catch(...){ }
            watching=false;
            std::printf("mode=%d copied=%d allocated=%d retired=%d dirty=%d success=%d\n",mode,copied,allocated,retired,dirty,success);
            bool expected=mode==0||mode==6;
            return copied>=12 && allocated>0 && dirty==0 && success==expected && (!success||correct) ? 0:1;
        }
        """#.utf8).write(to:source)
        // Raw string above contains C character escapes, not credential text.
        #if DEBUG
        let optimize="-O0"
        #else
        let optimize="-O2"
        #endif
        let cc=Process();cc.executableURL=URL(fileURLWithPath:"/usr/bin/clang++")
        cc.arguments=["-std=c++17",optimize,"-I",repo.appendingPathComponent("Tools/PAdESPrototype").path,source.path,"-o",binary.path]
        if let sanitizer=ProcessInfo.processInfo.environment["SIGNUM_TEST_PIN_PROBE_SANITIZER"], ["address","thread"].contains(sanitizer) {
            cc.arguments! += ["-fsanitize="+sanitizer,"-fno-omit-frame-pointer","-g"]
        }
        try cc.run();try FixtureProcess.wait(cc);XCTAssertEqual(cc.terminationStatus,0)
        for mode in success ? [0,6] : [1,2,3,4,5,7,8] {
            let p=Process();p.executableURL=binary;p.arguments=[String(mode)]
            let output=Pipe();p.standardOutput=output;try p.run();try FixtureProcess.wait(p)
            let result=String(decoding:output.fileHandleForReading.readDataToEndOfFile(),as:UTF8.self)
            print("S06 "+result.trimmingCharacters(in:.newlines))
            XCTAssertEqual(p.terminationStatus,0,"Owned partial/reallocated secret must be wiped before free; mode \(mode)")
        }
    }
    func testActualBatchServerErasesOwnedPageBeforeFinalizeOnEveryControlledExit() throws {
        for scenario in ["finish","eofCancel","signError","changedToken","changedCertificate","lostSession","idleTimeout"] {
            let root=try FixtureFiles.directory("s06-batch");defer{try? FileManager.default.removeItem(at:root)}
            let signer=try SoftwareSigner(folder:root)
            let phase: Int? = scenario == "signError" ? 16 : scenario == "lostSession" ? 7 : nil
            let mock=try MockModule(certificate:signer.der,privateKey:signer.rsaPrivateDER(),workerPhase:phase,
                workerEffect:scenario == "lostSession" ? 6:4,alwaysAuth:true,faultAfter:scenario == "lostSession" ? 2:1,strictContext:true)
            if scenario == "changedCertificate" {
                let other=try CertificateEligibilityTests.fixtures.get().der("otherSigner")
                other.withUnsafeBytes { mock.replaceCertificate($0.bindMemory(to:UInt8.self).baseAddress,$0.count,2) }
            }
            let inspected=try MiddlewareFileSecurity.inspect(mock.path.path,automatic:false)
            let jobs=try (0..<3).map{_ in BatchWorkerJob(id:UUID(),snapshotID:UUID(),sha256:String(repeating:"a",count:64),attributes:try CAdES.Prepared(document:Data("Synthetic batch wipe".utf8),certificateDER:signer.der).attributesToSign)}
            var start=BatchWorkerStart(version:3,batchID:UUID(),provider:inspected.canonicalPath,slot:7,
                serial:scenario == "changedToken" ? "OTHER-TOKEN":"SYNTHETIC-0001",certificate:.init(.init(label:"Synthetic",identifier:Data([1])),der:signer.der),automatic:false,moduleIdentity:inspected.identity,jobs:jobs,pin:nil)
            start.temporaryPIN=true
            if scenario == "idleTimeout" {start.pinIdleSeconds=0.05}
            func frame<T:Encodable>(_ value:T)throws->Data {
                let data=try JSONEncoder().encode(value)
                var out=Data((0..<4).reversed().map{UInt8((UInt32(data.count)>>($0*8))&255)});out.append(data);return out
            }
            var wire=try frame(start)
            let secret=Data([0x53,0x30,0x36,0x2d,0x77,0x69,0x70,0x65])
            wire.append(Data([0,0,0,UInt8(secret.count)]));wire.append(secret)
            if scenario != "eofCancel" && scenario != "idleTimeout" {
                for index in 1..<3 {wire.append(try frame(BatchWorkerCommand(version:2,batchID:start.batchID,jobID:jobs[index].id,index:index,finish:false)))}
                wire.append(try frame(BatchWorkerCommand(version:2,batchID:start.batchID,jobID:nil,index:3,finish:true)))
            }
            var input=[Int32](repeating:-1,count:2),output=[Int32](repeating:-1,count:2)
            XCTAssertEqual(pipe(&input),0);XCTAssertEqual(pipe(&output),0)
            defer{close(input[0]);if input[1]>=0{close(input[1])};close(output[0]);close(output[1])}
            XCTAssertEqual(wire.withUnsafeBytes{Darwin.write(input[1],$0.baseAddress,$0.count)},wire.count)
            if scenario != "idleTimeout" {close(input[1]);input[1] = -1}
            var erasures=0
            let result=BatchWorkerServer.serve(reply:output[1],inputDescriptor:input[0],onPINErasure:{page in
                erasures+=1;XCTAssertGreaterThan(page.count,64);XCTAssertTrue(page.allSatisfy{$0==0},scenario)
                XCTAssertEqual(mock.count(1),0,"Erase before Finalize")
            })
            XCTAssertEqual(erasures,1,scenario)
            XCTAssertEqual(result,(scenario == "finish" || scenario == "eofCancel") ? 0:2,scenario)
            XCTAssertLessThanOrEqual(mock.count(8),1)
            XCTAssertEqual(mock.count(16),scenario == "finish" ? 3:scenario == "changedToken" ? 0:scenario == "signError" ? 2:1,scenario)
        }
    }
    func testErasureIsIdempotentAndASecondBatchCannotBorrowTheClearedPIN() throws {
        var fds=[Int32](repeating:-1,count:2);XCTAssertEqual(pipe(&fds),0);defer{close(fds[0]);close(fds[1])}
        let frame:[UInt8]=[0,0,0,4,83,48,54,65]
        XCTAssertEqual(frame.withUnsafeBytes{Darwin.write(fds[1],$0.baseAddress,$0.count)},frame.count)
        var observed=0
        let secret=try WorkerBatchPINContext(lifetime:1,inputDescriptor:fds[0],onErasure:{page in
            observed+=1;XCTAssertTrue(page.allSatisfy{$0==0})
        })
        XCTAssertEqual(secret.length,4);secret.erase();secret.erase()
        XCTAssertNil(secret.bytes);XCTAssertEqual(secret.length,0);XCTAssertEqual(observed,1)
        // A new owner must receive a new frame, never the previous owner's bytes.
        close(fds[1]);fds[1] = -1
        XCTAssertThrowsError(try WorkerBatchPINContext(lifetime:0.05,inputDescriptor:fds[0]))
        XCTAssertEqual(secret.length,0)
    }

}
#endif
