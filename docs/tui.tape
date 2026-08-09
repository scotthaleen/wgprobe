Output tui.gif

Set Shell "zsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set TypingSpeed 40ms
Set Framerate 15

Type "./nordprobe --key-file .KEY"
Enter
Sleep 3s

Type "las vegas""
Sleep 1s
Enter
Sleep 2s

# Reduce the confirmation goal from three to one, then start probing.
Down
Down
Sleep 1s
Enter
Sleep 5s

# Export confirmed endpoints and hold on the exported result.
Type "e"
Sleep 4s

Ctrl+C
Sleep 4s
