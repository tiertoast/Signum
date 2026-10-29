/* Manual Beta launch gate: public AppKit process state, no AX or hardware APIs. */
#import <AppKit/AppKit.h>
#import <unistd.h>
int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 3) return 2;
        pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
        NSString *identifier = [NSString stringWithUTF8String:argv[2]];
        for (int i=0;i<100;i++) {
            NSRunningApplication *app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
            if (app && app.isTerminated) return 3;
            if (app && app.isFinishedLaunching && [app.bundleIdentifier isEqualToString:identifier]) {
                puts("finishedLaunching: verified owned PID and bundle identifier"); return 0;
            }
            usleep(100000);
        }
        return 4;
    }
}
