#if os(macOS)
import XCTest
import Darwin

/// A controlling TTY for the PIN, a separate stdin pipe for document consent.
/// Synthetic input travels through anonymous pipes only, never argv/env/files.
enum S03CLITerminalFixture {
    struct Result {
        let output: String
        let exit: Int
        let clean, protected, restored: Bool
        var error: String { output.components(separatedBy:.newlines).first{$0.hasPrefix("Signum error:")} ?? "" }
    }
    static func run(arguments: [String], root: URL, onReview: ((String) throws -> String)? = nil) throws -> Result {
        let script=root.appendingPathComponent("s03-consent-pty.py")
        try Data(#"""
        import os,sys,json,base64,time,select,termios,signal
        config=json.loads(sys.stdin.readline());secret=base64.b64decode(config['input'])
        reader,writer=os.pipe();pid,fd=os.forkpty()
        if pid==0:
            os.close(writer);os.dup2(reader,0);os.close(reader)
            os.execv(config['args'][0],config['args'])
        os.close(reader);initial=termios.tcgetattr(fd)
        output=b'';sent=False;reviewed=False;protected=False;status=None
        def emit(value):print(json.dumps(value),flush=True)
        deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([fd],[],[],0.02)
                if ready:
                    try:chunk=os.read(fd,8192)
                    except OSError:chunk=b''
                    output+=chunk
                    if not sent and b'Token PIN' in output and output.endswith(b': '):
                        protected=not bool(termios.tcgetattr(fd)[3]&termios.ECHO)
                        os.write(fd,secret+b'\n');sent=True
                    if sent and not reviewed and b'scrivi FIRMA' in output:
                        reviewed=True;emit({'event':'review','output':output.decode('utf-8','replace').replace(secret.decode('utf-8'),'[redacted]')})
                        response=json.loads(sys.stdin.readline());os.write(writer,response.encode('utf-8'));os.close(writer);writer=-1
                done,value=os.waitpid(pid,os.WNOHANG)
                if done:status=value;break
            if status is None:os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
            while select.select([fd],[],[],0)[0]:
                try:chunk=os.read(fd,8192)
                except OSError:break
                if not chunk:break
                output+=chunk
            emit({'event':'done','exit':os.waitstatus_to_exitcode(status),'output':output.decode('utf-8','replace').replace(secret.decode('utf-8'),'[redacted]'),'clean':secret not in output,'protected':protected,'restored':termios.tcgetattr(fd)==initial})
        finally:
            os.close(fd)
            if writer>=0:os.close(writer)
        """#.utf8).write(to:script)
        let process=Process(),input=Pipe(),output=Pipe()
        process.executableURL=URL(fileURLWithPath:"/usr/bin/python3");process.arguments=[script.path]
        process.standardInput=input;process.standardOutput=output;process.standardError=FileHandle.nullDevice
        try process.run()
        defer {if process.isRunning {kill(process.processIdentifier,SIGKILL);try? FixtureProcess.wait(process)}}
        func send(_ object: Any) throws {
            var data=try JSONSerialization.data(withJSONObject:object,options:.fragmentsAllowed);data.append(10)
            try input.fileHandleForWriting.write(contentsOf:data)
        }
        try send(["args":arguments,"input":Data([83,48,51,45,67,79,78,83,69,78,84]).base64EncodedString()])
        while true {
            var line=Data()
            while line.last != 10 {
                let next=output.fileHandleForReading.readData(ofLength:1)
                guard !next.isEmpty else {throw NSError(domain:"S03 terminal fixture ended",code:1)}
                line.append(next)
                guard line.count < 65536 else {throw NSError(domain:"S03 terminal fixture exceeded output limit",code:1)}
            }
            let event=try XCTUnwrap(JSONSerialization.jsonObject(with:line) as? [String:Any])
            if event["event"] as? String == "review" {
                let text=try XCTUnwrap(event["output"] as? String)
                try send(try onReview?(text) ?? "ANNULLA\n")
            } else {
                try input.fileHandleForWriting.close();try FixtureProcess.wait(process)
                XCTAssertEqual(process.terminationStatus,0)
                return Result(output:try XCTUnwrap(event["output"] as? String),exit:try XCTUnwrap(event["exit"] as? Int),
                    clean:try XCTUnwrap(event["clean"] as? Bool),protected:try XCTUnwrap(event["protected"] as? Bool),restored:try XCTUnwrap(event["restored"] as? Bool))
            }
        }
    }
}
#endif
