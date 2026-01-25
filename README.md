# SlipStream GUI Client

Minimal Windows GUI wrapper for SlipStream.

## Run

Place slipstream-client-windows-amd64.exe next to SlipstreamGUI.exe and launch:

```
SlipstreamGUI.exe
```

## Notes

- The GUI validates required fields before connecting.
- Logs and status update live.
                                              ↓
                         Log Streaming → LogsView → Display
                                              ↓
                         Status Updates → StatusView → Display
```

## Process Lifecycle

1. **Configuration**: User fills form and clicks CONNECT
2. **Validation**: Config is validated (required fields, ranges)
3. **Build Args**: Command-line arguments constructed from config
4. **Process Start**: Binary spawned with arguments
5. **Live Output**: stdout/stderr streamed to scrollable log view
6. **Status Updates**: PID, uptime, connection status updated 2x/sec
7. **User Control**: Restart (F5), disconnect (Ctrl+D), or quit
8. **Graceful Shutdown**: Process terminated and resources cleaned up

## Production Readiness

✅ **Code Quality**
- Clean separation of concerns
- Comprehensive error handling
- Resource cleanup on shutdown
- Goroutine-safe with proper synchronization
- Comments explaining complex logic

✅ **Process Management**
- Lock file prevents multiple instances
- Graceful signal handling (CTRL+C)
- Process group management on Windows
- Non-blocking output reading
- Bounded log buffer (10,000 lines max)

✅ **User Experience**
- Professional, clean layout
- Color-coded output streams
- Real-time status indicators
- Keyboard-only navigation
- Helpful error messages
- No crashes on invalid input

✅ **Performance**
- Efficient terminal rendering
- Non-blocking UI updates
- Bounded memory (capped log lines)
- Minimal CPU usage at rest

## Dependencies

Only two external Go packages:
- `github.com/charmbracelet/bubbletea`: TUI framework
- `github.com/charmbracelet/lipgloss`: Styling library

All other dependencies are standard Go libraries.

## Platform Support

Currently supports Windows amd64. The code is structured to allow easy porting to other platforms by adjusting:
- `syscall.SysProcAttr` for process group handling (line in `process/manager.go`)
- Signal handling (currently uses `os.Interrupt` which works cross-platform)

## Future Enhancements

Possible additions without core changes:
- Configuration file loading/saving (.json or YAML)
- Log filtering by stream type
- Search/grep in logs
- Configuration templates/presets
- Metrics dashboard
- Signal strength indicators
- Connection statistics
