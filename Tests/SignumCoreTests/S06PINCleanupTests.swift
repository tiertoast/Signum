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
        void operator delete(void*p) noexcept {for(int i=0;i<4096;i++)if(blocks[i]==p){if(sizes[i]&&((unsigned char*)p)[0]==0xa7)++dirty;blocks[i]=nullptr;++retired;break;}std::free(p);}
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
        try cc.run();try FixtureProcess.wait(cc);XCTAssertEqual(cc.terminationStatus,0)
        for mode in success ? [0,6] : [1,2,3,4,5,7,8] {
            let p=Process();p.executableURL=binary;p.arguments=[String(mode)]
            let output=Pipe();p.standardOutput=output;try p.run();try FixtureProcess.wait(p)
            let result=String(decoding:output.fileHandleForReading.readDataToEndOfFile(),as:UTF8.self)
            print("S06 "+result.trimmingCharacters(in:.newlines))
            XCTAssertEqual(p.terminationStatus,0,"Owned partial/reallocated secret must be wiped before free; mode \(mode)")
        }
    }
}
#endif
